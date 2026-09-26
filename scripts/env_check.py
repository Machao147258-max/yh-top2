import sys
sys.path.insert(0, r'D:\逆向工具\qiling\qiling-master')
import qiling
print('qiling OK', qiling.__version__)
from qiling import Qiling
from qiling.const import QL_VERBOSE
print('imports OK')
