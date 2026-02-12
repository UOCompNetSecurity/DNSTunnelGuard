
from dataclasses import dataclass, field

@dataclass 
class GramNode: 
    end_grams: set[str] = field(default_factory=set[str])
    grams: set[str] = field(default_factory=set[str])
    next_level: "GramNode | None" = None


class MatchGram: 
    """
    Tree data structure to store a large set of strings. 
    Used to check if a string exists in the set.  


    When a string is inserted, it is split into pieces of n size, called an n gram. 
    Each node represents a set of n grams, with n being the number of characters. 
    The nodes children are possible branches of the next n gram in the string. 


    """

    def __init__(self, gram_num: int): 
        self.root = GramNode()
        self.gram_num = gram_num


    def insert(self, word: str): 
        if not word: 
            return 

        grams = gram_string(word, self.gram_num)

        current = self.root

        for i in range(len(grams)): 
            if i == (len(grams) - 1): 
                current.end_grams.add(grams[i])
                break 

            current.grams.add(grams[i])
            current.next_level = GramNode()
            current = current.next_level



    def __contains__(self, word: str) -> bool: 
        return self.is_match(word)

    def is_match(self, word: str) -> bool: 

        grams = gram_string(word, self.gram_num)

        current = self.root 

        for i in range(len(grams)): 
            if i == (len(grams) - 1) and grams[i] in current.end_grams: 
                return True

            if grams[i] not in current.grams: 
                return False 

            if not current.next_level: 
                return False

            current = current.next_level

        return False



def gram_string(word: str, num: int): 
    split = [word[i:i+num] for i in range(len(word))]
    if len(split[-1]) != num: 
        split.pop()

        



                
                



            

















