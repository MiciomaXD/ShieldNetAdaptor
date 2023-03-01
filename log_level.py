from enum import Enum

class Level(Enum):
    """How much importance we want to give to our log fragments?"""
    NONE = None
    INFO = 'INFO'
    WARNING = 'WARNING'
    ERROR = 'ERROR'

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