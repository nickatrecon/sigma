# dump_rules_to_db.py
# Purpose: Read, parse, and dump rules stored in sigma_rules folder to database
# To run locally:
#   $ cp .env.example .env  # edit .env
#   $ python3 dump_rules_to_db.py

import json
import os
import sys
import time
from datetime import date
from pathlib import Path
from pprint import pformat

import psycopg2
import yaml
from anthropic import Anthropic
from dotenv import load_dotenv
from logger_config import setup_logger
from openai import BadRequestError, OpenAI

# logging.basicConfig(
#     stream=sys.stdout,
#     level=logging.INFO,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
# )
# logger = logging.getLogger(__name__)

logger = setup_logger()

load_dotenv()

DB_NAME = os.getenv("PG_DB_NAME")
DB_USER = os.getenv("PG_DB_USER")
DB_PASSWORD = os.getenv("PG_DB_PASSWORD")
DB_HOST = os.getenv("PG_DB_HOST")
DB_PORT = os.getenv("PG_DB_PORT")

RULES_DIR = os.path.join(Path(__file__).parent.parent, "rules")
TABLE_NAME = "hq_rules"
DEFAULT_MODEL = "gpt-4o-mini"

safe_load_failures = []
merged_rules = []
amended_rules = []
failed_summary_generation_filepaths = []

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SUMMARY_FORMAT = """
1. **Purpose**:
   - 30-word max summary of the rule's purpose.

2. **Event Sources**:
   - The sources of events that the rule monitors.

3. **Event IDs**:
   - List of event IDs that the rule triggers on.

4. **Detection Logic**:
   - Detailed and accurate explanation of the detection logic used in the rule.

5. **False Positives**:
   - Concise scenarios and likelihood of false positives.

6. **Severity Level**:
   - The severity level assigned to the rule and concise justification.

7. **References**:
   - List of references identified in the rule.

8. **Conclusion**:
    - 30-word max conclusion summarizing the rule.
"""

SUMMARY_GENERATION_PROMPT = """
<sigma_rule>
{rule}
</sigma_rule>

<summary_format>
{summary_format}
</summary_format>

Create a full detailed, natural-language description of what the above Sigma detection rule does and how it does it.
""".strip()


def connect_to_db():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
        )
        return conn
    except Exception as e:
        logger.error(f"Error when connecting to DB: {e}")
        sys.exit(1)


def create_table():
    """
    Create the table TABLE_NAME if it doesn't exist. The primary key is the uuid of the rule (rule['id']).
    """

    logger.debug("Creating table if it doesn't exist...")
    conn = connect_to_db()
    cur = conn.cursor()

    # Create table if it doesn't exist
    cur.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            filepath TEXT PRIMARY KEY,
            id TEXT,
            title TEXT,
            description TEXT,
            status TEXT,
            log_source JSONB,
            detection JSONB,
            level TEXT,
            tags TEXT[],
            rule_data JSONB,
            summary TEXT
        );
        """
    )

    conn.commit()

    cur.close()
    conn.close()


def escape_string(s):
    """Escape single quotes in a string for SQL insertion."""
    return s.replace("'", "''")


def default_serializer(obj):
    """Normalize JSON serialization for date objects."""
    if isinstance(obj, date):
        return f"{obj.year}/{obj.month:02d}/{obj.day:02d}"
    raise TypeError(f"Type {obj} not serializable")


def upsert_one_rule(rule: dict, conn, cur):
    """Upsert a single rule."""

    # Convert the rule to JSON; exclude the summary field
    rule_copy = rule.copy()
    rule_copy.pop("summary")
    rule_data = json.dumps(rule_copy, default=default_serializer)

    # Upsert the rule, using the rule ID and title as the primary key
    cur.execute(
        f"""
        INSERT INTO {TABLE_NAME} (filepath, id, title, description, status, log_source, detection, level, tags, rule_data, summary)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (filepath) DO UPDATE SET
            id = EXCLUDED.id,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            status = EXCLUDED.status,
            log_source = EXCLUDED.log_source,
            detection = EXCLUDED.detection,
            level = EXCLUDED.level,
            tags = EXCLUDED.tags,
            rule_data = EXCLUDED.rule_data,
            summary = EXCLUDED.summary;
        """,
        (
            rule["filepath"],
            rule["id"],
            escape_string(rule["title"]),
            escape_string(rule["description"]),
            rule.get("status", ""),
            json.dumps(rule["logsource"]),
            json.dumps(rule["detection"]),
            rule.get("level", ""),
            rule.get("tags", []) or [],  # Ensure tags is a list
            rule_data,
            rule.get("summary", ""),
        ),
    )

    conn.commit()


def safe_load_all_and_merge(f):
    """
    Safely load all YAML documents from a sigma rule file.
    If there are multiple documents, merge the documents.
    Note:
      - This is a workaround for the fact that some (very few) sigma rules have multiple documents.
      - This results in loss of data if the documents have the same keys.
    """
    try:
        loaded_doc = {}
        relative_path = os.path.relpath(f.name, RULES_DIR)
        documents = [d for d in yaml.safe_load_all(f)]

        if not documents:
            loaded_doc["filepath"] = relative_path
        elif len(documents) > 1:
            for doc in documents:
                if doc:
                    loaded_doc.update(doc)
            merged_rules.append(relative_path)
            loaded_doc["filepath"] = relative_path
        else:
            loaded_doc = documents[0]
            loaded_doc["filepath"] = relative_path

        return loaded_doc

    except yaml.YAMLError as e:
        logger.error(f"Error loading YAML: {e}")
        return {}


def post_process_yaml_to_dict(rule: dict):
    """Post-process a rule to ensure it has the correct format."""

    # Convert references to a list if it's a string
    if "references" in rule and isinstance(rule["references"], str):
        rule["references"] = [rule["references"]]


def post_process_recon(rule: dict):
    """Post-process a rule with Recon-specific logic."""

    # Convert status based on relative filepath
    fp = str(rule["filepath"])
    if fp.startswith("test") and rule["status"] != "test":
        rule["status"] = "test"
        amended_rules.append(fp)
    elif fp.startswith("staging") and rule["status"] != "stable":
        rule["status"] = "stable"
        amended_rules.append(fp)


def generate_summary(rule: dict, rule_contents, model=DEFAULT_MODEL):
    """Generate an AI summary for a rule from the raw rule file contents."""

    prompt = SUMMARY_GENERATION_PROMPT.format(
        rule=rule_contents, summary_format=SUMMARY_FORMAT
    )

    if model == "gpt-4o-mini":
        try:
            response = openai_client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt,
                            }
                        ],
                    }
                ],
                response_format={"type": "text"},
                temperature=0.1,
                max_completion_tokens=8192,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0,
            )
            response_text = response.choices[0].message.content
        except (BadRequestError, Exception) as bad_request_error:
            logger.error(f"OpenAI bad request error: {bad_request_error}")
            logger.error(f"Failed to generate summary for rule: {rule['filepath']}")
            logger.error(f"Prompt: {prompt}")
            failed_summary_generation_filepaths.append(rule["filepath"])
            response_text = ""

    elif model == "claude-3-haiku-20240307":
        try:
            response = anthropic_client.messages.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt,
                            }
                        ],
                    }
                ],
                temperature=0.1,
                max_tokens=4096,
                top_p=1,
            )
            response_text = response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic error: {e}")
            logger.error(f"Failed to generate summary for rule: {rule['filepath']}")
            logger.error(f"Prompt: {prompt}")
            failed_summary_generation_filepaths.append(rule["filepath"])
            response_text = ""

    else:
        logger.error(f"Invalid model: {model}")
        sys.exit(1)

    logger.info(f"Generated summary for rule: {rule['filepath']}")
    logger.info(f"Response: {response_text}")

    rule["summary"] = response_text


def dump_rules_to_db(
    limit: int = None,
    dry_run: bool = False,
    input_path: str = None,
    model: str = DEFAULT_MODEL,
):
    """Dump rules to the database."""
    conn = connect_to_db()
    cur = conn.cursor()

    if input_path:
        rule_files = [Path(input_path)]
        logger.info(f"Ingesting rule from: {input_path}")
    else:
        # Ingest rules from sigma_rules folder and subfolders
        rule_files = list(Path(RULES_DIR).rglob("*.yml"))
        logger.info(f"Ingesting rules from: {RULES_DIR}")

        if limit:
            rule_files = rule_files[:limit]

    # start a timer
    start = time.time()

    for f in rule_files:
        with open(f, "r") as rule_file:
            rule_contents = rule_file.read()
            # reset the file pointer to the beginning of the file
            rule_file.seek(0)
            rule = safe_load_all_and_merge(rule_file)
            if not rule:
                safe_load_failures.append(f)
                continue
            logger.info(f"Ingesting rule: {rule['filepath']}")

            post_process_yaml_to_dict(rule)
            post_process_recon(rule)
            generate_summary(rule, rule_contents, model=model)

            # Upsert the rule to the database or print the rule if it's a dry run
            if not dry_run:
                upsert_one_rule(rule, conn, cur)
                logger.info(f"Upserting rule: {rule}")
            else:
                logger.info(f"Rule: {rule}")

    # Log some stats
    end = time.time()
    logger.info(f"Time taken to ingest rules: {end - start} seconds")

    cur.execute(f"SELECT COUNT(*) FROM {TABLE_NAME};")
    count = cur.fetchone()[0]

    logger.info(f"Number of rules ingested: {count}")
    logger.info(f"Time per rule: {(end - start) / count} seconds")
    logger.info(f"Number of rules that failed to load: {len(safe_load_failures)}")
    logger.info(f"Number of merged rules: {len(merged_rules)}")
    logger.info(f"Number of amended rules: {len(amended_rules)}")
    logger.info(
        f"Number of failed summary generation: {len(failed_summary_generation_filepaths)}"
    )
    if merged_rules:
        logger.warning(f"Merged rules:\n{pformat(merged_rules)}")
    if safe_load_failures:
        logger.warning(f"Rules that failed to load:\n{pformat(safe_load_failures)}")
    if amended_rules:
        logger.info(f"Amended rules:\n{pformat(amended_rules)}")
    if failed_summary_generation_filepaths:
        logger.info(
            f"Failed summary generation rules:\n{pformat(failed_summary_generation_filepaths)}"
        )

    cur.close()
    conn.close()


def main():
    create_table()

    ## get --dry-run flag from command line arguments and pass it to dump_rules_to_db
    if "--dry-run" in sys.argv:
        dry_run = True
    else:
        dry_run = False

    ## get --limit flag from command line arguments and pass it to dump_rules_to_db
    if "--limit" in sys.argv:
        limit_index = sys.argv.index("--limit") + 1
        limit = int(sys.argv[limit_index])
    else:
        limit = None

    if "--input" in sys.argv:
        input_index = sys.argv.index("--input") + 1
        input_path = sys.argv[input_index]
    else:
        input_path = None

    if "--model" in sys.argv:
        model_index = sys.argv.index("--model") + 1
        model = sys.argv[model_index]
    else:
        model = None

    logger.info(f"Running with limit: {limit}, dry_run: {dry_run}")

    dump_rules_to_db(limit=limit, dry_run=dry_run, input_path=input_path, model=model)


if __name__ == "__main__":
    sys.exit(main())
