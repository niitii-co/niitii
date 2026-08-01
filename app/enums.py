from enum import Enum


class AccountPermission(Enum):
    READ = 1
    COMMENT = 2
    MESSAGE = 4
    WRITE = 8
    MODERATE = 16
    ADMIN = 32
    ROOT_ADMIN = 64


class UserViewer(Enum):
    PUBLIC = 1
    USER = 2
    FOLLOWER = 4


class PostViewer(Enum):
    PUBLIC = 1
    USER = 2
    FOLLOWER = 4


class FlagReason(Enum):
    NSFW = 1
    SPAM = 2
    VIOLENT = 3    


class UnicodeChar(Enum):
    PEDESTRIAN = '&#x1F6B6;&#xfe0e;'
    NOPEDESTRIANS = '&#x1F6B7;&#xfe0e;'
    
