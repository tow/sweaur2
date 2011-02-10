from token_store import TokenStore
from client_store import ClientStore
from policy import LowSecurityPolicy
from processor import OAuth2Processor

oauth_2_processor = OAuth2Processor(TokenStore(), ClientStore(), LowSecurityPolicy())
