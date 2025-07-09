import os
import argparse
import patoolib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

LOGS_DIR_NAME = "logs"
ERROR_LOG_FILENAME = "archive_errors.log"
ARCHIVE_EXTENSIONS = ('.zip', '.rar', '.7z')
DEFAULT_PASSWORD_FILE = 'passwords.txt'

def find_archive_files(directory):
    """Finds archive files in the given directory."""
    archives = []
    logging.info(f"Scanning for archives in directory: {directory}")
    try:
        for item in os.listdir(directory):
            if item.lower().endswith(ARCHIVE_EXTENSIONS):
                archives.append(os.path.join(directory, item))
        logging.info(f"Found {len(archives)} archive(s): {archives}")
    except FileNotFoundError:
        logging.error(f"Directory not found: {directory}")
    except Exception as e:
        logging.error(f"Error scanning directory {directory}: {e}")
    return archives

def find_password_file(directory, password_file_name=DEFAULT_PASSWORD_FILE):
    """Finds the specified password file in the given directory."""
    password_file_path = os.path.join(directory, password_file_name)
    if os.path.isfile(password_file_path):
        logging.info(f"Password file found: {password_file_path}")
        return password_file_path
    else:
        logging.warning(f"Password file '{password_file_name}' not found in {directory}.")
        return None

def read_passwords(password_file_path):
    """Reads passwords from the password file, stripping 'pass:' prefix."""
    passwords = []
    if password_file_path:
        try:
            # Specify UTF-8 encoding and ignore errors
            with open(password_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line.lower().startswith("pass:"):
                        password = stripped_line[5:].strip() # Get text after "pass:" and strip again
                        if password: # Ensure password is not empty after stripping "pass:"
                            passwords.append(password)
                        else:
                            logging.warning(f"Found 'pass:' prefix but password was empty in line: '{line.strip()}'")
                    elif stripped_line: # Non-empty line that doesn't start with "pass:"
                        # Decide if these should be treated as passwords or ignored.
                        # For now, let's assume lines without "pass:" are also potential passwords if not empty.
                        # If they should be ignored, this part can be removed.
                        passwords.append(stripped_line)
                        logging.info(f"Read password without 'pass:' prefix: '{stripped_line}'")

            logging.info(f"Read {len(passwords)} potential password(s) after processing prefixes.")
            if passwords:
                logging.debug(f"Passwords loaded: {passwords}") # Log actual passwords only at debug level
        except Exception as e:
            logging.error(f"Error reading password file {password_file_path}: {e}")
    return passwords

def ensure_logs_dir_exists(logs_dirname="logs"):
    """Ensures the logs directory exists, creating it if necessary."""
    # Determine path relative to the script's location for robustness
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir_path = os.path.join(script_dir, logs_dirname)

    if not os.path.exists(log_dir_path):
        try:
            os.makedirs(log_dir_path)
            logging.info(f"Created logs directory: {log_dir_path}")
        except OSError as e:
            logging.error(f"Failed to create logs directory {log_dir_path}: {e}")
            return None # Indicate failure
    return log_dir_path

def extract_single_archive(archive_path, passwords):
    """Extracts a single archive, trying passwords if necessary, and returns success status and error counts."""
    archive_name_no_ext = os.path.splitext(os.path.basename(archive_path))[0]
    output_dir = os.path.join(os.path.dirname(archive_path), archive_name_no_ext)
    error_counts = {} # Initialize error collection for this archive

    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logging.info(f"Created output directory: {output_dir}")
        else:
            logging.info(f"Output directory already exists: {output_dir}")

        # Attempt extraction without password first
        try:
            logging.info(f"Attempting to extract {archive_path} to {output_dir} without a password.")
            patoolib.extract_archive(archive_path, outdir=output_dir, verbosity=-1)
            logging.info(f"Successfully extracted {archive_path} without a password.")
            # If successful, call log_archive_errors with empty error_counts or handle appropriately
            # For now, this means no errors are logged to the file for this success case.
            return True, error_counts
        except patoolib.util.PatoolError as e:
            error_msg = str(e)
            error_counts[error_msg] = error_counts.get(error_msg, 0) + 1
            logging.warning(f"Failed to extract {archive_path} without a password: {error_msg}. Trying passwords if available.")
            if not passwords:
                logging.error(f"No passwords available to try for {archive_path}.")
                return False, error_counts
        except Exception as e: # Catch other unexpected errors during no-password attempt
            error_msg = f"Unexpected error during no-password extraction: {str(e)}"
            error_counts[error_msg] = error_counts.get(error_msg, 0) + 1
            logging.error(f"Error extracting {archive_path} without password: {error_msg}")
            if not passwords:
                return False, error_counts


        # Try with passwords if the no-password attempt failed and passwords are provided
        if passwords:
            for i, password in enumerate(passwords):
                try:
                    # Note: Verbose logging of password itself should be for temporary debugging if needed
                    # logging.info(f"Attempting to extract {archive_path} with password #{i+1}: '{password}'...")
                    logging.info(f"Attempting to extract {archive_path} with password #{i+1}...")
                    patoolib.extract_archive(archive_path, outdir=output_dir, verbosity=-1, password=password)
                    logging.info(f"Successfully extracted {archive_path} with password #{i+1}.")
                    return True, error_counts
                except patoolib.util.PatoolError as e:
                    error_msg = str(e)
                    error_counts[error_msg] = error_counts.get(error_msg, 0) + 1
                    logging.warning(f"Password #{i+1} failed for {archive_path}.") # Console log remains minimal
                except Exception as e: # Catch other potential errors from patoolib
                    error_msg = f"Unexpected error with password #{i+1}: {str(e)}"
                    error_counts[error_msg] = error_counts.get(error_msg, 0) + 1
                    logging.error(f"Error extracting {archive_path} with password #{i+1}: {error_msg}")
                    continue # Continue to next password

            logging.error(f"All passwords failed for {archive_path}.")
            return False, error_counts

        # This part is reached if no-password attempt failed AND there were no passwords to try.
        # Errors from the no-password attempt would have been collected.
        return False, error_counts


    except Exception as e: # Catch errors related to directory creation or other setup
        error_msg = f"Outer error during extraction process for {archive_path}: {str(e)}"
        # This error is outside the password attempts, so it's a general failure for the archive.
        error_counts[error_msg] = error_counts.get(error_msg, 0) + 1
        logging.error(error_msg)
        return False, error_counts
    # The 'finally' block was removed as it's not strictly needed here;
    # error_counts are returned directly.

def log_archive_errors(archive_filename, error_counts, error_log_filepath):
    """Appends error summaries for a given archive to the specified log file."""
    if not error_counts:
        return # No errors to log for this archive

    try:
        with open(error_log_filepath, 'a', encoding='utf-8') as f:
            for error_message, count in error_counts.items():
                # Sanitize error_message to remove newlines for cleaner CSV-like logging if desired,
                # or ensure it's properly quoted if it can contain commas.
                # For plain text log, direct write is fine.
                clean_error_message = str(error_message).replace('\\n', ' ').replace('\\r', '')
                f.write(f"File: {archive_filename}, Error: \"{clean_error_message}\", Count: {count}\\n")
        logging.info(f"Error summary for {archive_filename} written to {error_log_filepath}")
    except Exception as e:
        logging.error(f"Failed to write error summary for {archive_filename} to {error_log_filepath}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Extracts .zip, .rar, and .7z archives in a directory, using passwords from a file.")
    # Make directory argument optional
    parser.add_argument("-d", "--directory",
                        help="The directory containing archives and the password file. Defaults to script's own directory.")
    parser.add_argument("--pwfile", default=DEFAULT_PASSWORD_FILE,
                        help=f"Name of the password file (default: {DEFAULT_PASSWORD_FILE}).")

    args = parser.parse_args()
    password_file_name = args.pwfile

    if args.directory:
        target_directory = args.directory
    else:
        # Default to the script's own directory
        script_path = os.path.abspath(__file__)
        target_directory = os.path.dirname(script_path)
        logging.info(f"No directory specified, defaulting to script directory: {target_directory}")

    if not os.path.isdir(target_directory):
        logging.error(f"Determined path '{target_directory}' is not a valid directory.")
        return

    archive_files = find_archive_files(target_directory)
    if not archive_files:
        logging.info("No archive files found to process.")
        return

    password_file_path = find_password_file(target_directory, password_file_name)
    passwords = []
    if password_file_path:
        passwords = read_passwords(password_file_path)
    else:
        logging.warning(f"Proceeding without passwords as '{password_file_name}' was not found.")

    successful_extractions = 0
    failed_extractions = 0

    # Ensure the logs directory exists and get its path
    logs_dir_path = ensure_logs_dir_exists(LOGS_DIR_NAME)
    if not logs_dir_path:
        logging.error("Could not create or access logs directory. Detailed error logging to file will be disabled.")
        # Optionally, decide if the script should exit or continue without file logging.
        # For now, it will continue, and log_archive_errors will gracefully handle a None path if we design it so,
        # or we simply don't call it. Let's ensure error_log_filepath is valid before calling.

    error_log_filepath = None
    if logs_dir_path:
        error_log_filepath = os.path.join(logs_dir_path, ERROR_LOG_FILENAME)
        logging.info(f"Archive error summaries will be logged to: {error_log_filepath}")


    for archive_path in archive_files:
        logging.info(f"Processing archive: {archive_path}")
        # Pass error_log_filepath to extract_single_archive - actually, not needed, it returns errors
        # The error_log_path parameter in extract_single_archive was for an alternative design.
        # Removing it from its signature as it's not used there.

        # The function signature for extract_single_archive was:
        # def extract_single_archive(archive_path, passwords, error_log_path):
        # Let's adjust it if error_log_path is no longer passed.
        # For now, assuming it's still in the signature as per previous steps, but will be ignored.
        # It should be: def extract_single_archive(archive_path, passwords):

        success_status, collected_errors = extract_single_archive(archive_path, passwords)

        if success_status:
            successful_extractions += 1
        else:
            failed_extractions += 1
            # Optional cleanup logic can remain here

        # Log collected errors for this archive, if the log file path is valid
        if error_log_filepath and collected_errors: # Only log if there were errors
            log_archive_errors(os.path.basename(archive_path), collected_errors, error_log_filepath)


    logging.info("--------------------------------------------------")
    logging.info(f"Extraction summary:")
    logging.info(f"  Successfully extracted: {successful_extractions} archive(s)")
    logging.info(f"  Failed to extract:      {failed_extractions} archive(s)")
    logging.info("--------------------------------------------------")

if __name__ == "__main__":
    main()
