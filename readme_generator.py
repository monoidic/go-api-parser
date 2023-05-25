import ast
import markdown


def get_docstrings(source):
    """Walks through the abstract syntax tree to retrieve docstrings."""
    docstrings = {}

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str):
                docstrings[node.name] = node.body[0].value.s

    return docstrings


def create_readme(filename):
    """Creates a README.md file using docstrings from Python code."""
    with open(filename, 'r') as f:
        source = f.read()

    docstrings = get_docstrings(source)

    with open('README.md', 'w') as f:
        for name, docstring in docstrings.items():
            md_docstring = markdown.markdown(docstring)
            f.write(f"# {name}\n\n{md_docstring}\n\n")


# usage:
create_readme('params.py')
