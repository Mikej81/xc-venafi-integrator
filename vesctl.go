package main

import (
	"fmt"
	"os"
	"os/exec"
)

// runShellCommand executes the 'vesctl' command with provided arguments.
func runShellCommand(command, outputFilePath string) error {
	// Open the output file
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Execute the command using 'bash -c'
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = outputFile // Redirect stdout to the file
	cmd.Stderr = os.Stderr  // Redirect stderr to see errors in the console

	// Run the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error executing command: %v", err)
	}

	return nil
}
