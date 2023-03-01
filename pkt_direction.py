from enum import Enum

class PacketDirection(Enum):
    """Direction of the packet: forward: 1, backwards: 0"""
    FWD = 1
    BWD = 0

"""
# printing enum member as string
print(Level.INFO)
 
# printing name of enum member using "name" keyword
print(Level.INFO.name)
 
# printing value of enum member using "value" keyword
print(Level.INFO.value)
 
# printing the type of enum member using type()
print(type(Level.INFO))
 
# printing enum member as repr
print(repr(Level.INFO))
 
# printing all enum member using "list" keyword
print(list(Level))
"""