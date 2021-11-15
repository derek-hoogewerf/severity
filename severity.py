#################################################################################################################################################################
# This script set up severities by condition.                                                                                                                   #
# To add new condition you need to add new dict to Severities list in format:                                                                                   #
#           {                                                                                                                                                   #
#              "severity":"Minor",  -   Severity you want to setup, and can have 4 values (look severity_code field): Informational, Minor, Major, Critical     #
#              "Conditions":[       -   List of conditions by what you need to setup severity                                                                   #
#                  {"field":"domain_id","value":"60"} - condition list, always must contain 2 keys:                                                             #
#                                                        field - must contain name of field (API Access Name) you want to check                                 #
#                                                        value - value of field you want to Match                                                               #
#                                                        Operation for conditions is "contain" so be care in condition                                          #
#              ],                                                                                                                                               #
#              "query":"1 AND (2 OR 3)"               - OPTIONAL. Use this field if you need some custom condition, you can use operators and ()                #
#                                                       always use SPACE (" ") to separate arguments and operators                                              #
#                                                       If there is no this key, all conditions will be joined by AND                                           #
#                                                       If you need to join all condition by OR, you can just set this field to OR like this:                   #
#                                                       "query":"OR"                                                                                            #
#            }                                                                                                                                                  #
# Please setup a comment with description of each new Conditions dict you add to list                                                                           #
#################################################################################################################################################################

Severities = [
            # Ding requirement:
            {
              "severity": "Minor",
              "Conditions":[
                  {"field": "domain_id", "value": "60"},
                  {"field": "description","value": "O365"},
                  {"field": "description","value": "VPN"},
              ],
              "query": "1 AND (2 OR 3)"
            }
            ]


# Parser for queries
def Eval_parse(subquery):
  start = subquery.find('(')
  if start>=0:
    # Solve all expressions in () first
    fin = subquery.find(')', start)
    der = subquery[start:fin+1]
    subquery = subquery.replace(der, parse_query(der[1:])) # replace expressions in () to solved value
    subquery = Eval_parse(subquery)                       # Recursive execution to search other ()
  else:
    # Solve explession after delete all () 
    subquery = parse_query(subquery)
  return subquery
  
# boolean expression solver
def parse_query(s):
  boolVal={"True": True,"False": False}
  s=s.replace(')','').replace('(','').split(' ') 
  k=True
  while k:
    k=False
    for r in range(0,len(s)):
      f=""
      if s[r]=="AND":
        f=str(boolVal[s[r-1]] and boolVal[s[r+1]])
      elif s[r]=="OR":
        f=str(boolVal[s[r-1]] or boolVal[s[r+1]])
      if f!="":
        s[r]=f
        del(s[r+1])
        del(s[r-1])
        k=True  
        break
  return s[0]

for r in Severities:
  query=""
  boolVal={"True":True,"False":False}
  s=1
  if "query" not in r.keys():
    for cond in r["Conditions"]:
      query+=str(s)+" AND "
      s+=1
    query=query[0:-5]
    s=1
  elif r["query"] == "OR":
    for cond in r["Conditions"]:
      query+=str(s)+" OR "
      s+=1
    query=query[0:-4]
    s=1
  else:
    query=r["query"]
  
  for cond in r["Conditions"]:
    if cond["field"]=='description':
      val=str(incident.description)
    elif cond["field"]=='name':
      val=str(incident.name)
    else:
      val=str(incident.properties[cond["field"]])
    if val.find(cond["value"])>=0:
      query=query.replace(str(s),'True')
    else:
      query=query.replace(str(s),'False')
    s+=1
  #Dumb Protection:
  query=query.replace("( ","(").replace(" )",")")
  query=query.replace("AND"," AND ").replace("OR"," OR ")
  query=query.replace("   "," ").replace("  "," ")
  res=Eval_parse(query)
  if boolVal[res]:
    incident.properties.severity_code = r["severity"]
    break
  #log.debug(res)
