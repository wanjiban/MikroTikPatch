"""
包管理模块

本模块提供在修补过程中管理 Python 包依赖项的实用工具。支持的功

- 检查包是否已安装
- 使用 pip 安装包
- 安装特定版本
- 使用自定义 PyPI 索引

这些函数设计用于在修补工作流中工作，确保所需依赖项（如 pefile、pyelftools）可用。
"""


def install_package(package, version="upgrade", index_url='https://mirrors.aliyun.com/pypi/simple/'):
    """
    使用 pip 安装或升级 Python 包。

    此函数处理新安装和版本升级。
    它使用当前 Python 解释器的 pip 模块。

    参数:
        package: 要安装的包名称
        version: 版本说明符。使用 "upgrade"（默认）安装最新版本
                或指定版本如 ">=1.0.0"
        index_url: PyPI 索引 URL（默认为阿里云镜像）

    返回:
        int: pip 返回码（0 表示成功，非零表示失败）

    示例:
        >>> install_package('pefile')
        >>> install_package('pyelftools', '>=1.6.0')
    """
    from sys import executable
    from subprocess import check_call
    result = False
    try:
        if version.lower() == "upgrade":
            result = check_call([executable, "-m", "pip", "install", package,
                                "--upgrade", "-i", index_url])
        else:
            from pkg_resources import get_distribution
            current_package_version = None
            try:
                current_package_version = get_distribution(package)
            except Exception:
                pass
            if current_package_version is None or current_package_version != version:
                installation_sign = "==" if ">=" not in version else ""
                result = check_call([executable, "-m", "pip", "install",
                                    package + installation_sign + version,
                                    "-i", index_url])
    except Exception as e:
        print(e)
        result = -1
    return result


def check_package(package):
    """
    检查是否安装了 Python 包。

    参数:
        package: 要检查的包名称

    返回:
        bool: 如果包已安装返回 True，否则返回 False

    示例:
        >>> check_package('pefile')
        True
        >>> check_package('nonexistent')
        False
    """
    from importlib import import_module
    try:
        import_module(package)
        return True
    except ImportError:
        return False


def check_install_package(packages):
    """
    检查并在缺少时安装多个包。

    这是一个便利函数，检查列表中每个包的状态，
    并安装任何当前未安装的包。

    参数:
        packages: 要检查和安装的包名称列表

    示例:
        >>> check_install_package(['pefile', 'pyelftools'])
        # 安装任何缺少的包
    """
    for package in packages:
        if not check_package(package):
            install_package(package)
