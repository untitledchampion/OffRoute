// The app's executable: embeds the bundled Python and runs Resources/app/main.py in this very process,
// so macOS sees the app itself (its name and icon), not a separate python binary.
#include <Python.h>
#include <libgen.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char exe[PATH_MAX], real[PATH_MAX], home[PATH_MAX], script[PATH_MAX];
    uint32_t size = sizeof(exe);
    if (_NSGetExecutablePath(exe, &size) != 0 || realpath(exe, real) == NULL) {
        fprintf(stderr, "OffRoute: cannot find itself\n");
        return 1;
    }
    char *dir = dirname(real);  // .../Contents/MacOS
    snprintf(home, sizeof(home), "%s/../Resources/python", dir);
    snprintf(script, sizeof(script), "%s/../Resources/app/main.py", dir);
    setenv("PYTHONHOME", home, 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    unsetenv("PYTHONPATH");

    char **args = calloc((size_t)argc + 3, sizeof(char *));
    int n = 0;
    args[n++] = argv[0];
    args[n++] = "-s";  // no user site-packages
    args[n++] = script;
    for (int i = 1; i < argc; i++) args[n++] = argv[i];
    args[n] = NULL;
    return Py_BytesMain(n, args);
}
