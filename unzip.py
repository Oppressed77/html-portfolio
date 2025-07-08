import os
import argparse
import patoolib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    """Reads passwords from the password file, one per line."""
    passwords = []
    if password_file_path:
        try:
            with open(password_file_path, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            logging.info(f"Read {len(passwords)} password(s).")
        except Exception as e:
            logging.error(f"Error reading password file {password_file_path}: {e}")
    return passwords

def extract_single_archive(archive_path, passwords):
    """Extracts a single archive, trying passwords if necessary."""
    archive_name_no_ext = os.path.splitext(os.path.basename(archive_path))[0]
    output_dir = os.path.join(os.path.dirname(archive_path), archive_name_no_ext)

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
            return True
        except patoolib.util.PatoolError as e:
            logging.warning(f"Failed to extract {archive_path} without a password: {e}. Trying passwords if available.")
            if not passwords:
                logging.error(f"No passwords available to try for {archive_path}.")
                return False

        # Try with passwords
        for i, password in enumerate(passwords):
            try:
                logging.info(f"Attempting to extract {archive_path} with password #{i+1}...")
                patoolib.extract_archive(archive_path, outdir=output_dir, verbosity=-1, password=password)
                logging.info(f"Successfully extracted {archive_path} with password #{i+1}.")
                return True
            except patoolib.util.PatoolError:
                logging.warning(f"Password #{i+1} failed for {archive_path}.")
            except Exception as e: # Catch other potential errors from patoolib
                logging.error(f"An unexpected error occurred during extraction of {archive_path} with password #{i+1}: {e}")
                # Continue to next password if one specific password causes non-PatoolError
                continue

        logging.error(f"All passwords failed for {archive_path}.")
        return False

    except Exception as e:
        logging.error(f"An error occurred during the extraction process for {archive_path}: {e}")
        return False

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

    for archive_path in archive_files:
        logging.info(f"Processing archive: {archive_path}")
        if extract_single_archive(archive_path, passwords):
            successful_extractions += 1
        else:
            failed_extractions += 1
            # Optional: Clean up empty output directory if extraction failed
            # archive_name_no_ext = os.path.splitext(os.path.basename(archive_path))[0]
            # potential_output_dir = os.path.join(os.path.dirname(archive_path), archive_name_no_ext)
            # if os.path.exists(potential_output_dir) and not os.listdir(potential_output_dir):
            #     logging.info(f"Cleaning up empty directory: {potential_output_dir}")
            #     try:
            #         os.rmdir(potential_output_dir)
            #     except OSError as e:
            #         logging.error(f"Could not remove directory {potential_output_dir}: {e}")


    logging.info("--------------------------------------------------")
    logging.info(f"Extraction summary:")
    logging.info(f"  Successfully extracted: {successful_extractions} archive(s)")
    logging.info(f"  Failed to extract:      {failed_extractions} archive(s)")
    logging.info("--------------------------------------------------")

if __name__ == "__main__":
    main()
