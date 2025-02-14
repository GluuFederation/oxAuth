# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
# Modified: Zico
# This script is adding new users into specific group inside Gluu Server

from org.gluu.model.custom.script.type.user import CacheRefreshType
from org.gluu.util import StringHelper, ArrayHelper
from java.util import Arrays, ArrayList
from org.gluu.oxtrust.model import GluuCustomAttribute
from org.gluu.model.custom.script.model.bind import BindCredentials
from org.gluu.oxtrust.service import GroupService
from org.gluu.service.cdi.util import CdiUtil

import java

class CacheRefresh(CacheRefreshType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Cache refresh. Initialization"
        self.groupService = CdiUtil.bean(GroupService)
        print "Cache refresh. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "Cache refresh. Destroy"
        print "Cache refresh. Destroyed successfully"
        return True

    def isStartProcess(self, configurationAttributes):
        print "Cache refresh. Is start process method"
        return False
    
    def getBindCredentials(self, configId, configurationAttributes):
        print "Cache refresh. GetBindCredentials method"
        return None

    def updateUser(self, user, configurationAttributes):
        print "Cache refresh. UpdateUser method"

        attributes = user.getCustomAttributes()
        
        # Ensure user is part of 'Second test group'
        group_inum = "inum=419aae93-6c39-4512-bd65-9628a61f40d3,ou=groups,o=gluu"
        group = self.groupService.getGroupByDn(group_inum)
        user_dn = user.getDn()
        
        is_member_group = self.isUserMemberOfGroup(group, user_dn)
        print "!!!!!!!!!!!", is_member_group
        
        if not is_member_group:
            print "User is NOT a member of the group. Adding now..."
            current_members = group.getMembers()
            if current_members is None:
                current_members = ArrayList()
            
            current_members.add(user_dn)
            group.setMembers(current_members)
            self.groupService.updateGroup(group)
            print "User successfully added to the group!"
        
        return True

    def isUserMemberOfGroup(self, group, user_dn):
        is_member = False
        member_of_list = group.getMembers()
        if member_of_list is not None:
            for member in member_of_list:
                if StringHelper.equalsIgnoreCase(user_dn, member) or member.endswith(user_dn):
                    is_member = True
                    break
        return is_member

    def getApiVersion(self):
        return 11
