import json
import updategraph as ug

#We assume root node is identical to both, equivalent to a user node
def createUpgradeState(initial,target):
    root = initial.makeCopy(2)
    newList = []
    for child in initial.listOfChildren:
        if(target.exists(child.node)):
            newList.append(ug.childAndSec(child.node.makeCopy(2), child.secLevel))
        else:
            newList.append(ug.childAndSec(child.node.makeCopy(0), child.secLevel))
    for child in target.listOfChildren:
        if(child.node.marked==False):
            newList.append(ug.childAndSec(child.node.makeCopy(1), child.secLevel))
    for newChild in newList:
        newChild.node.listOfChildren=ug.findChildren(newChild.node,initial,target)
    root.listOfChildren=newList
    return root
            
#takes the output of parseJSON, and sets the origin_security fields
def setSecurityLevels(node):
    if(node.listOfChildren):
        for child in node.listOfChildren:
            level=node.higherLevel(node.origin_security,child.secLevel)
            level=node.higherLevel(level,child.node.origin_security)
            child.node.origin_security=level
            setSecurityLevels(child.node)



init = input("Enter the contract configuration JSON file for the initial state: ")
target = input("Enter the contract configuration JSON file for the updated state: ")


A1=ug.parseJSON(init)
A2=ug.parseJSON(target)
setSecurityLevels(A1)
setSecurityLevels(A2)
A=createUpgradeState(A1,A2)
A.checkChildren()



