import json

#Origin is 0 if from source, 1 if from 1 target, 2 if identical in both
#Security is transformed here into a number
#Identical names means identical proxy contracts
class Node:
    def __init__(self, name, origin , origin_security=0, listOfChildren=None, marked=False):
        self.listOfChildren=listOfChildren;
        self.name=name
        self.origin=origin
        self.origin_security = origin_security
        self.actual_security = -1
        self.marked=marked
    def higherLevel(self,sec1,sec2):
        if(sec1>sec2):
            return sec1
        else:
            return sec2
    def makeCopy(self, newOrigin):
        return Node(self.name, newOrigin,self.origin_security, None, False)
    def exists(self, node):
        if(self.listOfChildren!=None):
            for child in self.listOfChildren:
                if(child.node.name==node.name and child.node.origin_security==node.origin_security):
                    child.node.marked=True
                    return True
        return False
    def printMe(self, stri =""):
        print(stri+ self.name + "(" + str(self.origin_security)+")")
        if(self.listOfChildren):
            for child in self.listOfChildren:
                child.node.printMe(stri+' ')
    def checkChildren(self):
        if(self.listOfChildren!=None):
            for child in self.listOfChildren:
                if(child.node.origin_security < self.higherLevel(self.actual_security,child.secLevel)):
                    if(self.origin==1):
                        print("Vulnerability found: "+ self.name + " must update before " + child.node.name)
                    elif(self.origin==0):
                        print("Vulnerability found: "+ child.node.name + " must update before " + self.name)
                else:
                    child.node.actual_security=self.higherLevel(self.actual_security,child.secLevel)
                    child.node.checkChildren()
#data struct in listOfChildren, stores node and, if connection is authenticated, required security level to access
class childAndSec:
    def __init__(self, child=None, secLevel=0):
        self.node=child
        self.secLevel=secLevel
def findChildren(node,graph1,graph2):
    node1 = findNode(node,graph1)
    node2 = findNode(node,graph2)
    newList = []
    if(node1!=None and node1.listOfChildren!=None):
        for child in node1.listOfChildren:
            
            if(node2!=None and node2.exists(child.node)):
                newList.append(childAndSec(child.node.makeCopy(2), child.secLevel))
            else:
                newList.append(childAndSec(child.node.makeCopy(0), child.secLevel))
        if(node2!=None):
            for child in node2.listOfChildren:
                if(child.node.marked==False):
                    newList.append(childAndSec(child.node.makeCopy(1), child.secLevel))
    elif(node2!=None and node2.listOfChildren!=None):
        for child in node2.listOfChildren:
            newList.append(childAndSec(child.node.makeCopy(1), child.secLevel))
    else:
        return None
    for newChild in newList:
        newChild.node.listOfChildren=findChildren(newChild.node,graph1,graph2)
    return newList
    
def findNode(node, graph):
    key = node.name
    if(graph.listOfChildren==None):
        return None
    else:
        for child in graph.listOfChildren:
            if(child.node.name==key):
                return child.node
            lookChildren = findNode(node, child.node)
            if(lookChildren!=None):
                return lookChildren
        return None
def isInList(name, nodeList):
    for n in nodeList:
        if(n.name==name):
            return n
    return None
def parseJSON(jString):
    y=json.loads(jString)
    z=(y['contracts'])
    returnNode = None
    isFirst=True
    listOfNodes=[]
    for res in z:
        nodeName=res['name']
        listOfKids=None
        if "children" in res:
            listOfKids=[]
            for child in res["children"]:
                newNode=isInList(child["name"], listOfNodes)
                if(newNode):
                    newConnection=childAndSec(newNode,child["connect_sec"])
                    listOfKids.append(newConnection)
                else:
                    newNode=Node(child["name"],2,-1,None)
                    newConnection=childAndSec(newNode,child["connect_sec"])
                    listOfKids.append(newConnection)
                    listOfNodes.append(newNode)
                #make list of children, checking listOfNodes each time to avoid duplicates INCOMPLETE
                #if it exists, just edit that one instead of creating a new one INCOMPLETE
        newNode=isInList(nodeName,listOfNodes)
        if(newNode):
            newNode.listOfChildren=listOfKids
        else:
            newNode=Node(nodeName,2,-1,listOfKids)
            listOfNodes.append(newNode)
        if(isFirst):
            returnNode=newNode
            isFirst=False
    return returnNode
