import json
from pathlib import Path
from sys import platform
from invoke.context import Context
from invoke.tasks import task
from sslyze import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx: Context) -> None:
    ctx.run("pytest --cov=sslyze --cov-fail-under 80 --durations 5")


@task
def lint(ctx: Context) -> None:
    ctx.run("ruff format . --check")
    ctx.run("ruff check .")
    ctx.run("mypy .")


@task
def autoformat(ctx: Context) -> None:
    ctx.run("ruff format .")
    ctx.run("ruff check . --fix")


@task
def gen_doc(ctx: Context) -> None:
    docs_folder_path = root_path / "docs"
    dst_path = docs_folder_path / "documentation"
    ctx.run(f"python -m sphinx -v -b html {docs_folder_path} {dst_path}")


@task
def release(ctx: Context) -> None:
    response = input(f'Release version "{__version__}" ? y/n')
    if response.lower() != "y":
        print("Cancelled")
        return

    # Ensure the tests pass
    test(ctx)

    # Ensure the API samples work
    ctx.run("python api_sample.py")

    # Add the git tag
    ctx.run(f"git tag -a {__version__} -m '{__version__}'")
    ctx.run("git push --tags")

    # Generate the doc
    gen_doc(ctx)

    # Upload to Pypi
    ctx.run("python setup.py sdist")
    sdist_path = root_path / "dist" / f"sslyze-{__version__}.tar.gz"
    ctx.run(f"twine upload {sdist_path}")


@task
def build_exe(ctx: Context) -> None:
    if platform != "win32":
        raise EnvironmentError("Can only be used on Windows")
    # WARNING(AD): This does not work well within a pipenv and the system's Python should be used
    ctx.run("python setup.py build_exe")


@task
def gen_json_schema(ctx: Context) -> None:
    from sslyze.json.json_output import SslyzeOutputAsJson

    json_schema = SslyzeOutputAsJson.model_json_schema()
    json_schema_file = Path(__file__).parent / "json_output_schema.json"
    json_schema_file.write_text(json.dumps(json_schema, indent=2))
