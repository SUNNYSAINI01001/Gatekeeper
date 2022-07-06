import sys
for x in range(1,256):
    sys.stdout.write("\\x" + '{:02x}'.format(x))
