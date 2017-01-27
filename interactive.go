package main

import (
    "io"
    "fmt"
    "strconv"
    "golang.org/x/crypto/ssh/terminal"
)

func InteractiveSelection(c io.ReadWriter, prompt string, choices []string) (string, error) {
    t := terminal.NewTerminal(c, "Please Enter A Server ID: ")

    fmt.Fprintf(c, "%s\r\n", prompt)
    for i, v := range choices {
        fmt.Fprintf(c, "    [ %2d ] %s\r\n", i+1, v)
    }

    var ct int = 0
    for {
        // Only allow a maxmimum of 3 attempts.
        if ct > 3 {
            fmt.Fprintf(c, "Maximum Number of Attempts Reached\r\n")
            return "", fmt.Errorf("Maximum Number of Attempts Reached")
        } else {
            ct += 1
        }

        sel, err := t.ReadLine()
        if err != nil {
            return "", err
        }

        i, err := strconv.Atoi(sel)
        if err != nil {
            continue
        }

        if (i < 0) || (i > len(choices)) {
            continue
        } else {
            return choices[(i-1)], err
        }
    }
}
