from __future__ import with_statement
from contextlib import contextmanager
from datetime import datetime
from UserDict import DictMixin

import bcrypt
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import Unicode
from sqlalchemy import func
from sqlalchemy.sql.expression import or_
from sqlalchemy.orm.exc import NoResultFound
from pyramid.location import lineage
from pyramid.security import authenticated_userid, ALL_PERMISSIONS
from pyramid.security import has_permission as base_has_permission
from pyramid.security import view_execution_permitted

from kotti import get_settings
from kotti import DBSession
from kotti import Base
from kotti.sqla import JsonType
from kotti.util import _
from kotti.util import request_cache
from kotti.util import DontCache


def get_principals():
    return get_settings()['kotti.principals_factory'][0]()


@request_cache(lambda request: None)
def get_user(request):
    userid = authenticated_userid(request)
    return get_principals().get(userid)


def has_permission(permission, context, request):
    with authz_context(context, request):
        return base_has_permission(permission, context, request)


class Principal(Base):
    """A minimal 'Principal' implementation.

    The attributes on this object correspond to what one ought to
    implement to get full support by the system.  You're free to add
    additional attributes.

      - As convenience, when passing 'password' in the initializer, it
        is hashed using 'get_principals().hash_password'

      - The boolean 'active' attribute defines whether a principal may
        log in.  This allows the deactivation of accounts without
        deleting them.

      - The 'confirm_token' attribute is set whenever a user has
        forgotten their password.  This token is used to identify the
        receiver of the email.  This attribute should be set to
        'None' once confirmation has succeeded.
    """
    __tablename__ = 'principals'
    __mapper_args__ = dict(
        order_by='principals.name',
        )

    id = Column(Integer, primary_key=True)
    name = Column(Unicode(100), unique=True)
    password = Column(Unicode(100))
    active = Column(Boolean)
    confirm_token = Column(Unicode(100))
    title = Column(Unicode(100), nullable=False)
    email = Column(Unicode(100), unique=True)
    groups = Column(JsonType(), nullable=False)
    creation_date = Column(DateTime(), nullable=False)
    last_login_date = Column(DateTime())

    def __init__(self, name, password=None, active=True, confirm_token=None,
                 title=u"", email=None, groups=()):
        self.name = name
        if password is not None:
            password = get_principals().hash_password(password)
        self.password = password
        self.active = active
        self.confirm_token = confirm_token
        self.title = title
        self.email = email
        self.groups = groups
        self.creation_date = datetime.now()
        self.last_login_date = None

    def __repr__(self):  # pragma: no cover
        return '<Principal %r>' % self.name

    @property
    def all_groups(self):
        return list_groups(self.name)


class AbstractPrincipals(object):
    """This class serves as documentation and defines what methods are
    expected from a Principals database.

    Principals mostly provides dict-like access to the principal
    objects in the database.  In addition, there's the 'search' method
    which allows searching users and groups.

    'hash_password' is for initial hashing of a clear text password,
    while 'validate_password' is used by the login to see if the
    entered password matches the hashed password that's already in the
    database.

    Use the 'kotti.principals' settings variable to override Kotti's
    default Principals implementation with your own.
    """
    def __getitem__(self, name):
        """Return the Principal object with the id 'name'.
        """

    def __setitem__(self, name, principal):
        """Add a given Principal object to the database.

        'name' is expected to the the same as 'principal.name'.

        'principal' may also be a dict of attributes.
        """

    def __delitem__(self, name):
        """Remove the principal with the given name from the database.
        """

    def keys(self):
        """Return a list of principal ids that are in the database.
        """

    def search(self, **kwargs):
        """Return an iterable with principal objects that correspond
        to the search arguments passed in.

        This example would return all principals with the id 'bob':

          get_principals().search(name=u'bob')

        Here, we ask for all principals that have 'bob' in either
        their 'name' or their 'title'.  We pass '*bob*' instead of
        'bob' to indicate that we want case-insensitive substring
        matching:

          get_principals().search(name=u'*bob*', title=u'*bob*')

        This call should fail with AttributeError unless there's a
        'foo' attribute on principal objects that supports search:

          get_principals().search(name=u'bob', foo=u'bar')
        """

    def hash_password(self, password):
        """Return a hash of the given password.

        This is what's stored in the database as 'principal.password'.
        """

    def validate_password(self, clear, hashed):
        """Returns True if the clear text password matches the hash.
        """

ROLES = {
    u'role:viewer': Principal(u'role:viewer', title=_(u'Viewer')),
    u'role:author': Principal(u'role:author', title=_(u'Author')),
    u'role:editor': Principal(u'role:editor', title=_(u'Editor')),
    u'role:owner': Principal(u'role:owner', title=_(u'Owner')),
    u'role:admin': Principal(u'role:admin', title=_(u'Admin')),
    }
_DEFAULT_ROLES = ROLES.copy()

# These roles are visible in the sharing tab
SHARING_ROLES = [u'role:viewer', u'role:author', u'role:editor']
USER_MANAGEMENT_ROLES = SHARING_ROLES + ['role:admin']
_DEFAULT_SHARING_ROLES = SHARING_ROLES[:]
_DEFAULT_USER_MANAGEMENT_ROLES = USER_MANAGEMENT_ROLES[:]
PERMISSIONS=['view', 'add', 'edit', 'manage', 'state_change']

# This is the ACL that gets set on the site root on creation.  Note
# that this is only really useful if you're _not_ using workflow.  If
# you are, then you should look at the permissions in workflow.zcml.
SITE_ACL = [
    ['Allow', 'system.Everyone', ['view']],
    ['Allow', 'role:viewer', ['view']],
    ['Allow', 'role:author', ['view', 'add']],
    ['Allow', 'role:editor', ['view', 'add', 'edit', 'state_change']],
    ['Allow', 'role:owner', ['view', 'edit', 'manage', 'state_change']],
    ]

def set_roles(roles_dict):
    ROLES.clear()
    ROLES.update(roles_dict)


def set_sharing_roles(role_names):
    SHARING_ROLES[:] = role_names


def set_user_management_roles(role_names):
    USER_MANAGEMENT_ROLES[:] = role_names


def reset_roles():
    ROLES.clear()
    ROLES.update(_DEFAULT_ROLES)


def reset_sharing_roles():
    SHARING_ROLES[:] = _DEFAULT_SHARING_ROLES


def reset_user_management_roles():
    USER_MANAGEMENT_ROLES[:] = _DEFAULT_USER_MANAGEMENT_ROLES


def reset():
    reset_roles()
    reset_sharing_roles()
    reset_user_management_roles()


class PersistentACLMixin(object):
    def _get_acl(self):
        if self._acl is None:
            raise AttributeError('__acl__')
        return self._acl

    def _set_acl(self, value):
        self._acl = value

    def _del_acl(self):
        self._acl = None

    __acl__ = property(_get_acl, _set_acl, _del_acl)


def list_groups(name, context=None):
    """List groups for principal with a given ``name``.

    The optional ``context`` argument may be passed to check owner
    of a given context.
    """
    def _find_owner(context):
        """ Node has no 'owner' attribute, so considered owned by owner
            of closest parent Content node
        """
        owner = None
        for location in lineage(context):
            if hasattr(location, '__owner__'):
                owner = location.__owner__
                break
        return owner

    principal = get_principals().get(name)
    groups = set(principal.groups)

    # Add inherited groups
    queue = principal.groups[:]
    while len(queue) > 0:
        new = []
        for group in queue:
            if not group.startswith('role:'):
                parent = get_principals().get(group)
                if parent is not None:
                    groups.update(parent.groups)
                    new.extend(parent.groups)
        queue = new

    # Add 'owner' role
    if context is not None:
        owner = _find_owner(context)
        if owner == name:
            groups.add('role:owner')
    return groups

def list_groups_ext(name, context=None):
    principal = get_principals().get(name)
    ext = set(list_groups(name)) - set(principal.groups)
    return principal.groups, ext

list_groups_raw = list_groups

def list_groups_callback(name, request):
    if not is_user(name):
        return None  # Disallow logging in with groups
    if name in get_principals():
        context = request.environ.get(
            'authz_context', getattr(request, 'context', None))
    return list_groups(name, context)

@contextmanager
def authz_context(context, request):
    before = request.environ.pop('authz_context', None)
    request.environ['authz_context'] = context
    try:
        yield
    finally:
        del request.environ['authz_context']
        if before is not None:
            request.environ['authz_context'] = before

def view_permitted(context, request, name=''):
    with authz_context(context, request):
        return view_execution_permitted(context, request, name)


def is_user(principal):
    if not isinstance(principal, basestring):
        principal = principal.name
    return ':' not in principal


class Principals(DictMixin):
    """Kotti's default principal database.

    Look at 'AbstractPrincipals' for documentation.

    This is a default implementation that may be replaced by using the
    'kotti.principals' settings variable.
    """
    factory = Principal

    @request_cache(lambda self, name: name)
    def __getitem__(self, name):
        name = unicode(name)
        try:
            return DBSession.query(
                self.factory).filter(self.factory.name == name).one()
        except NoResultFound:
            raise KeyError(name)

    def __setitem__(self, name, principal):
        name = unicode(name)
        if isinstance(principal, dict):
            principal = self.factory(**principal)
        DBSession.add(principal)

    def __delitem__(self, name):
        name = unicode(name)
        try:
            principal = DBSession.query(
                self.factory).filter(self.factory.name == name).one()
            DBSession.delete(principal)
        except NoResultFound:
            raise KeyError(name)

    def iterkeys(self):
        for (principal_name,) in DBSession.query(self.factory.name):
            yield principal_name

    def keys(self):
        return list(self.iterkeys())

    def search(self, **kwargs):
        if not kwargs:
            return []

        filters = []
        for key, value in kwargs.items():
            col = getattr(self.factory, key)
            if '*' in value:
                value = value.replace('*', '%').lower()
                filters.append(func.lower(col).like(value))
            else:
                filters.append(col == value)

        query = DBSession.query(self.factory)
        query = query.filter(or_(*filters))
        return query

    log_rounds = 10

    def hash_password(self, password, hashed=None):
        if hashed is None:
            hashed = bcrypt.gensalt(self.log_rounds)
        return unicode(
            bcrypt.hashpw(password.encode('utf-8'), hashed.encode('utf-8')))

    def validate_password(self, clear, hashed):
        try:
            return self.hash_password(clear, hashed) == hashed
        except ValueError:
            return False


def principals_factory():
    return Principals()

def acl_search(acl, principal, all_permissions=None):
    """ Search ACL for ACE with given principal, optional all_permission
        additionally require that permissions is ALL_PERMISSIONS if
        all_permissions=True or isn't if all_permissions=False
        Returns ACE position in ACL and ACE on success and (-1, None)
        otherwise
    """
    for i, ace in enumerate(acl):
        if ace[1] == principal:
            if all_permissions is None or (
                all_permissions and ace[2] == ALL_PERMISSIONS) or (
                not all_permissions and ace[2] != ALL_PERMISSIONS ):
                return i, ace
    return -1, None

