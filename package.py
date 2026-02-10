"""
Package Management Module

This module provides utilities for managing Python package dependencies
during the patching process. It supports:

- Checking if a package is installed
- Installing packages with pip
- Installing specific versions
- Using custom PyPI indexes

The functions are designed to work within the patching workflow,
ensuring required dependencies (like pefile, pyelftools) are available.
"""


def install_package(package, version="upgrade", index_url='https://mirrors.aliyun.com/pypi/simple/'):
    """
    Installs or upgrades a Python package using pip.

    This function handles both fresh installations and version upgrades.
    It uses the current Python interpreter's pip module.

    Args:
        package: Name of the package to install.
        version: Version specifier. Use "upgrade" (default) to install latest
                or specify a version like ">=1.0.0".
        index_url: PyPI index URL (default: Aliyun mirror).

    Returns:
        int: Return code from pip (0 for success, non-zero for failure).

    Example:
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
    Checks if a Python package is installed.

    Args:
        package: Name of the package to check.

    Returns:
        bool: True if package is installed, False otherwise.

    Example:
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
    Checks and installs multiple packages if missing.

    This is a convenience function that checks each package in the list
    and installs any that are not currently installed.

    Args:
        packages: List of package names to check and install.

    Example:
        >>> check_install_package(['pefile', 'pyelftools'])
        # Installs any missing packages
    """
    for package in packages:
        if not check_package(package):
            install_package(package)
