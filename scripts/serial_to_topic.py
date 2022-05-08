import sys
command_topics = 10;
command_topic_prefix = "agent_monitoring_{0}"
ascii_sum = 0;
if len(sys.argv) != 2:
    print ("must supply router serial")
    exit(1)
serial =  sys.argv[1]
for c in serial:
    ascii_sum += ord(c);

print (command_topic_prefix.format(ascii_sum % command_topics))
