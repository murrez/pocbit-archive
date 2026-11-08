while true; do
  ./scanner -p 80 -q -w all.zone | ./boa 80
done