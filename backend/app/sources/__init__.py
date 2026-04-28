from .avd import AvdHighRiskAdapter
from .chaitin import ChaitinVuldbAdapter
from .cisa_kev import CisaKevAdapter
from .cnvd import CnvdListAdapter
from .doonsec import DoonsecWechatRssAdapter
from .github import GitHubSecurityAdvisoriesAdapter
from .nvd import NvdRecentAdapter
from .oscs import OscsIntelAdapter
from .rss_biu import BiuProductCatalogAdapter, BiuRssAdapter
from .seebug import SeebugVuldbAdapter
from .stable_feeds import (
    CxsecurityRssAdapter,
    GitHubSecurityLabAdvisoriesAdapter,
    GobyVulsGitHubAdapter,
    SploitusRssAdapter,
)
from .struts2 import Struts2BulletinAdapter
from .threatbook import ThreatbookVulnAdapter
from .venustech import VenustechNoticeAdapter


ADAPTERS = [
    CisaKevAdapter(),
    BiuRssAdapter(),
    BiuProductCatalogAdapter(),
    GitHubSecurityAdvisoriesAdapter(),
    NvdRecentAdapter(),
    ChaitinVuldbAdapter(),
    OscsIntelAdapter(),
    ThreatbookVulnAdapter(),
    SeebugVuldbAdapter(),
    AvdHighRiskAdapter(),
    CnvdListAdapter(),
    DoonsecWechatRssAdapter(),
    SploitusRssAdapter(),
    CxsecurityRssAdapter(),
    GobyVulsGitHubAdapter(),
    GitHubSecurityLabAdvisoriesAdapter(),
    VenustechNoticeAdapter(),
    Struts2BulletinAdapter(),
]
