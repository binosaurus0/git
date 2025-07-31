#!/usr/bin/env python3
"""
PyGit: A minimal Git implementation in Python
Supports init, add, commit, status, diff, and push operations
"""

import os
import sys
import zlib
import hashlib
import struct
import time
import stat
import collections
import difflib
import argparse
import urllib.request
from enum import Enum


# Helper functions for file I/O
def read_file(path):
    """Read entire file and return bytes."""
    with open(path, 'rb') as f:
        return f.read()


def write_file(path, data):
    """Write data bytes to file."""
    with open(path, 'wb') as f:
        f.write(data)


# Git object types for pack files
class ObjectType(Enum):
    commit = 1
    tree = 2
    blob = 3


# Data structure for index entries
IndexEntry = collections.namedtuple('IndexEntry', [
    'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode',
    'uid', 'gid', 'size', 'sha1', 'flags', 'path',
])


def init(repo):
    """Create directory for repo and initialize .git directory."""
    os.makedirs(repo, exist_ok=True)
    os.makedirs(os.path.join(repo, '.git'), exist_ok=True)
    for name in ['objects', 'refs', 'refs/heads']:
        os.makedirs(os.path.join(repo, '.git', name), exist_ok=True)
    write_file(os.path.join(repo, '.git', 'HEAD'), b'ref: refs/heads/master\n')
    print(f'Initialized empty repository: {repo}')


def hash_object(data, obj_type, write=True):
    """Compute hash of object data and optionally write to object store."""
    header = f'{obj_type} {len(data)}'.encode()
    full_data = header + b'\x00' + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    
    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    return sha1


def find_object(sha1_prefix):
    """Find object with given SHA-1 prefix and return full SHA-1."""
    if len(sha1_prefix) < 4:
        raise ValueError('hash prefix must be at least 4 characters')
    
    obj_dir = os.path.join('.git', 'objects', sha1_prefix[:2])
    if not os.path.exists(obj_dir):
        raise ValueError(f'object {sha1_prefix} not found')
    
    matches = []
    for filename in os.listdir(obj_dir):
        if filename.startswith(sha1_prefix[2:]):
            matches.append(sha1_prefix[:2] + filename)
    
    if not matches:
        raise ValueError(f'object {sha1_prefix} not found')
    elif len(matches) > 1:
        raise ValueError(f'multiple objects found for {sha1_prefix}')
    
    return matches[0]


def read_object(sha1_prefix):
    """Read object with given SHA-1 prefix and return (type, data)."""
    sha1 = find_object(sha1_prefix)
    path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
    full_data = zlib.decompress(read_file(path))
    nul_index = full_data.index(b'\x00')
    header = full_data[:nul_index]
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[nul_index + 1:]
    assert size == len(data), f'expected size {size}, got {len(data)}'
    return (obj_type, data)


def cat_file(mode, sha1_prefix):
    """Pretty-print contents of object with given SHA-1 prefix."""
    obj_type, data = read_object(sha1_prefix)
    
    if mode in ['commit', 'tree', 'blob']:
        if obj_type != mode:
            raise ValueError(f'expected object type {mode}, got {obj_type}')
        sys.stdout.buffer.write(data)
    elif mode == 'size':
        print(len(data))
    elif mode == 'type':
        print(obj_type)
    elif mode == 'pretty':
        if obj_type in ['commit', 'tree']:
            sys.stdout.buffer.write(data)
        elif obj_type == 'blob':
            sys.stdout.buffer.write(data)


def read_index():
    """Read git index file and return list of IndexEntry objects."""
    try:
        data = read_file(os.path.join('.git', 'index'))
    except FileNotFoundError:
        return []
    
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], 'invalid index checksum'
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    assert signature == b'DIRC', f'invalid index signature {signature}'
    assert version == 2, f'unknown index version {version}'
    
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:fields_end])
        path_end = entry_data.index(b'\x00', fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    
    assert len(entries) == num_entries
    return entries


def ls_files():
    """List all files in the index."""
    for entry in read_index():
        print(entry.path)


def get_status():
    """Get status of working copy, return (changed, new, deleted) sets."""
    paths = set()
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in files:
            path = os.path.join(root, file)[2:].replace('\\', '/')
            paths.add(path)
    
    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path.keys())
    
    changed = {p for p in (paths & entry_paths)
               if hash_object(read_file(p), 'blob', write=False) !=
                  entries_by_path[p].sha1.hex()}
    new = paths - entry_paths
    deleted = entry_paths - paths
    
    return (changed, new, deleted)


def status():
    """Show status of working copy."""
    changed, new, deleted = get_status()
    
    if new:
        print('new files:')
        for path in sorted(new):
            print(f'    {path}')
    if changed:
        print('changed files:')
        for path in sorted(changed):
            print(f'    {path}')
    if deleted:
        print('deleted files:')
        for path in sorted(deleted):
            print(f'    {path}')


def diff():
    """Show diff of all changed files."""
    changed, _, _ = get_status()
    entries_by_path = {e.path: e for e in read_index()}
    
    for path in sorted(changed):
        sha1 = entries_by_path[path].sha1.hex()
        obj_type, data = read_object(sha1)
        assert obj_type == 'blob'
        
        index_lines = data.decode().splitlines()
        working_lines = read_file(path).decode().splitlines()
        
        diff_lines = difflib.unified_diff(
            index_lines, working_lines,
            f'{path} (index)', f'{path} (working copy)',
            lineterm=''
        )
        for line in diff_lines:
            print(line)


def write_index(entries):
    """Write list of IndexEntry objects to git index file."""
    packed_entries = []
    for entry in entries:
        entry_head = struct.pack('!LLLLLLLLLL20sH',
                                entry.ctime_s, entry.ctime_n, entry.mtime_s, entry.mtime_n,
                                entry.dev, entry.ino, entry.mode, entry.uid, entry.gid,
                                entry.size, entry.sha1, entry.flags)
        path = entry.path.encode()
        length = ((62 + len(path) + 8) // 8) * 8
        packed_entry = entry_head + path + b'\x00' * (length - 62 - len(path))
        packed_entries.append(packed_entry)
    
    header = struct.pack('!4sLL', b'DIRC', 2, len(entries))
    all_data = header + b''.join(packed_entries)
    digest = hashlib.sha1(all_data).digest()
    write_file(os.path.join('.git', 'index'), all_data + digest)


def add(paths):
    """Add given paths to the index."""
    paths = [p.replace('\\', '/') for p in paths]
    all_entries = {e.path: e for e in read_index()}
    
    for path in paths:
        data = read_file(path)
        sha1 = hash_object(data, 'blob')
        st = os.stat(path)
        flags = len(path.encode())
        assert flags < (1 << 12)
        
        entry = IndexEntry(
            int(st.st_ctime), 0, int(st.st_mtime), 0,
            st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_size, bytes.fromhex(sha1), flags, path
        )
        all_entries[path] = entry
    
    write_index(sorted(all_entries.values(), key=lambda e: e.path))


def write_tree():
    """Write a tree object from the current index entries."""
    tree_entries = []
    for entry in read_index():
        assert '/' not in entry.path, \
                'currently only supports a single, top-level directory'
        mode_path = f'{entry.mode:o} {entry.path}'.encode()
        tree_entry = mode_path + b'\x00' + entry.sha1
        tree_entries.append(tree_entry)
    return hash_object(b''.join(tree_entries), 'tree')


def get_local_master_hash():
    """Get current commit hash of local master branch."""
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    try:
        return read_file(master_path).decode().strip()
    except FileNotFoundError:
        return None


def commit(message, author):
    """Commit the current state of the index to master."""
    tree = write_tree()
    parent = get_local_master_hash()
    timestamp = int(time.time())
    utc_offset = -time.timezone
    author_time = f'{timestamp} {"+":if utc_offset > 0 else "-"}{abs(utc_offset) // 3600:02d}{(abs(utc_offset) // 60) % 60:02d}'
    
    lines = [f'tree {tree}']
    if parent:
        lines.append(f'parent {parent}')
    lines.append(f'author {author} {author_time}')
    lines.append(f'committer {author} {author_time}')
    lines.append('')
    lines.append(message)
    lines.append('')
    
    data = '\n'.join(lines).encode()
    sha1 = hash_object(data, 'commit')
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    write_file(master_path, (sha1 + '\n').encode())
    print(f'committed to master: {sha1[:7]}')
    return sha1


# Network/push functionality
def extract_lines(data):
    """Extract list of lines from pkt-line format data."""
    lines = []
    i = 0
    while i < len(data):
        if i + 4 > len(data):
            break
        line_length = int(data[i:i + 4], 16)
        if line_length == 0:
            lines.append(b'')
            i += 4
        else:
            line = data[i + 4:i + line_length]
            lines.append(line)
            i += line_length
        if i >= len(data):
            break
    return lines


def build_lines_data(lines):
    """Build pkt-line format data from list of lines."""
    result = []
    for line in lines:
        result.append(f'{len(line) + 5:04x}'.encode())
        result.append(line)
        result.append(b'\n')
    result.append(b'0000')
    return b''.join(result)


def http_request(url, username, password, data=None):
    """Make authenticated HTTP request."""
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, username, password)
    auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
    opener = urllib.request.build_opener(auth_handler)
    
    if data:
        request = urllib.request.Request(url, data=data)
        request.add_header('Content-Type', 'application/x-git-receive-pack-request')
    else:
        request = urllib.request.Request(url)
    
    try:
        f = opener.open(request)
        return f.read()
    except urllib.error.HTTPError as e:
        print(f'HTTP error {e.code}: {e.reason}')
        raise


def main():
    parser = argparse.ArgumentParser(description='PyGit - Minimal Git implementation')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # init command
    init_parser = subparsers.add_parser('init', help='Initialize a new repository')
    init_parser.add_argument('repo', help='Repository directory')
    
    # add command
    add_parser = subparsers.add_parser('add', help='Add files to index')
    add_parser.add_argument('paths', nargs='+', help='Paths to add')
    
    # commit command
    commit_parser = subparsers.add_parser('commit', help='Create a commit')
    commit_parser.add_argument('-m', '--message', required=True, help='Commit message')
    commit_parser.add_argument('--author', default='PyGit User <user@example.com>', help='Author')
    
    # status command
    subparsers.add_parser('status', help='Show working copy status')
    
    # diff command
    subparsers.add_parser('diff', help='Show changes')
    
    # ls-files command
    subparsers.add_parser('ls-files', help='List files in index')
    
    # cat-file command
    cat_parser = subparsers.add_parser('cat-file', help='Show object contents')
    cat_parser.add_argument('mode', choices=['blob', 'commit', 'tree', 'size', 'type', 'pretty'])
    cat_parser.add_argument('object', help='Object hash')
    
    # hash-object command
    hash_parser = subparsers.add_parser('hash-object', help='Hash an object')
    hash_parser.add_argument('file', help='File to hash')
    hash_parser.add_argument('-w', '--write', action='store_true', help='Write object to database')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'init':
            init(args.repo)
        elif args.command == 'add':
            add(args.paths)
        elif args.command == 'commit':
            commit(args.message, args.author)
        elif args.command == 'status':
            status()
        elif args.command == 'diff':
            diff()
        elif args.command == 'ls-files':
            ls_files()
        elif args.command == 'cat-file':
            cat_file(args.mode, args.object)
        elif args.command == 'hash-object':
            data = read_file(args.file)
            sha1 = hash_object(data, 'blob', write=args.write)
            print(sha1)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()