#!/usr/bin/env python3


"""
canonicalize an input file
"""
import xml.etree.ElementTree


import click

@click.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
def cli(filename):
    print(filename)

    with open(f"c14n_{filename}", mode='w', encoding='utf-8') as out_file:
        print(f"writing c14n_{filename}")
        xml.etree.ElementTree.canonicalize(from_file=filename, out=out_file)

if __name__ == '__main__':

    cli()