

/* Execute a specific command from environment variable */
void execute_command_from_env(const char *server_ip) {
    comm_init(server_ip, PORT);

    // Send initial hash
    char *initial_hash = calculate_program_hash();
    if (initial_hash) {
        printf("Initial hash: %s\n", initial_hash);
        if (comm_send_hash(initial_hash, 1) != 0) {
            fprintf(stderr, "Initial hash verification failed\n");
            free(initial_hash);
            comm_cleanup();
            exit(EXIT_FAILURE);
        }
        free(initial_hash);
    }

    // Get command from environment variable
    const char *command = getenv("COMMAND");
    if (command) {
        printf("Executing command: %s\n", command);
        comm_send_command(command);
    } else {
        printf("No command specified in environment.\n");
    }

    comm_cleanup();
}

/* Modify your main function to check for environment variable */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    const char *command = getenv("COMMAND");
    if (command) {
        // Execute specific command from environment
        execute_command_from_env(argv[1]);
    } else {
        // Execute the default sequence
        execute_sequence(argv[1]);
    }
    
    return EXIT_SUCCESS;
}
