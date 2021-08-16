# Securonix backend for sigmac 

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sigma
from sigma.parser.condition import ConditionOR
from .base import SingleTextQueryBackend
from ..parser.modifiers.base import SigmaTypeModifier


class SecuronixBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Securonix Spotter search"""
    reEscape = re.compile('(["\\\()])')
    identifier = "securonix"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = " NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = '"%s"'
    containsExpression = "%s CONTAINS %s"
    startsWithExpression = "%s STARTS WITH %s"
    endsWithExpression = "%s ENDS WITH %s"
    nullExpression = "%s NULL"
    notNullExpression = "%s NOT NULL"
    mapExpression = "%s = %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s = %s"
    functionalityCount = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        aFL = ["rg_functionality"]
        self.default_field = "rawevent"

        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    def generateNode(self, node):
        # print("node is {}".format(node))
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        elif type(node) in (str, int):
            return self.generateValueNode(node, False)
        elif type(node) == list:
            return self.generateListNode(node)
        elif isinstance(node, SigmaTypeModifier):
            return self.generateTypedValueNode(node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    # Skip logsource value from sigma document for separate path.
    def generateCleanValueNodeLogsource(self, value):
        return self.valueExpression % (self.cleanValue(str(value)))

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""

        # Retrieve the value of fields from the rule and generate spotter query
        fields, mappedAttribute = self.generateQueryforFields(sigmaparser)

        result = ""
        try:
            timeframe = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            timeframe = None
        for parsed in sigmaparser.condparsed:
            result = self.generateQuery(parsed, timeframe)

        if result is None or result.find("rg_functionality") == -1:
            print("Logsource mapping not found in configuration file.\n")
            return

        if mappedAttribute is not None:
            result += fields

        # appending index value
        index = self.appendIndexinQuery(result.find("rawevent"))
        result = index + result

        # replace escape characters due to "\"
        result = result.replace("\\\\", "\\").replace("\\\"", "\"").replace("\"\\\\", "\"\\").replace("\?","?").replace("\*","*")

        # replace escape characters due to "(" and ")"
        result = result.replace("\(", "(").replace("\)", ")")

        return result

    def sigma_to_spotter(self, line):
        key_words=["CONTAINS ", "IN ", "BETWEEN ", "ENDS WITH ", "STARTS WITH ", "EQUALS ", "NULL "]
        if("NOT (" in line):
            sigma = line
            query = ""
            fetched = 0
            while True:
                if("NOT (" in sigma):
                    query += sigma[fetched:sigma.find("NOT")]
                    fetched =  sigma.find("NOT")
                    s_half = sigma[fetched+3:]
                    within_brackets = s_half[:s_half.find(")")+1]
                    within_brackets_len = len(within_brackets)
                    for i in key_words:
                        within_brackets = within_brackets.replace(i,"NOT "+i)
                    query += within_brackets
                    fetched+= within_brackets_len
                    sigma = sigma.replace("NOT","",1)
                else:
                    query+=sigma[fetched:]
                    break
            return query
        else:
            return line

    def generateQuery(self, parsed, timeframe):
        self.functionalityCount = 0
        result = self.generateNode(parsed.parsedSearch)
        if result and parsed.parsedAgg:
            result += self.generateAggregation(parsed.parsedAgg, timeframe)
        query = self.sigma_to_spotter(str(result))
        return query

    # Generate Query for Fields
    def generateQueryforFields(self, sigmaparser):
        columns = list()
        notMapped = list()
        mappedAttr = None
        fields = ""
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mappedAttr = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if mappedAttr == field:
                    notMapped.append(field)
                if type(mappedAttr) == str:
                    columns.append(mappedAttr)
                elif type(mappedAttr) == list:
                    columns.extend(mappedAttr)
                else:
                    raise TypeError("Field mapping must return string or list")

            fields = ",".join(str(x) for x in columns)
            fields = " | TABLE " + fields

            if len(notMapped) > 0:
                consoleOutput = "No attribute mapping found for "
                consoleOutput += ", ".join(notMapped)
                consoleOutput += " in configuration file."
                print(consoleOutput, "\n")

        except KeyError:  # no 'fields' attribute
            mappedAttr = None
            pass

        return fields, mappedAttr

    # Appending index value in the output Query
    def appendIndexinQuery(self, findRawevent):
        if findRawevent != -1:
            index = "index = archive AND "
        else:
            index = "index = activity AND "
        return index

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if key == "rg_functionality":
                if self.functionalityCount > 0:
                    return
                self.functionalityCount += 1
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                return self.generateQueryForWildcardRule(key, value)
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif value is None:
                return self.nullExpression % (key,)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            # Rawevent change begins
            key = self.default_field
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                return self.generateRaweventQueryforStringInteger(key, value)
            elif isinstance(value, list):
                return self.generateMapItemListNode(key, value)
            elif value is None:
                return
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # Function to generate Spotter query for CONTAINS, ENDS WITH, STARTS WITH
    def generateQueryForWildcardRule(self, key, value):
        # contains expression, checking length in case only a wildcard is provided as field value
        if isinstance(value, str) and value.startswith("*") and value.endswith("*") and len(value) > 1:
            outputValue = self.cleanValue(re.sub("^\*|\*$", "", value))
            if self.isWildCardPresent(outputValue):
                return self.mapExpression % (key, self.generateValueNode("*{}*".format(outputValue), True))
            return self.containsExpression % (key, self.generateValueNode(outputValue, True))
        # endswith expression, checking length in case only a wildcard is provided as field value
        elif isinstance(value, str) and value.startswith("*") and len(value) > 1:
            outputValue = self.cleanValue(re.sub("^\*|\*$", "", value))
            if self.isWildCardPresent(outputValue):
                return self.mapExpression % (key, self.generateValueNode("*{}".format(outputValue), True))
            return self.endsWithExpression % (key, self.generateValueNode(outputValue, True))
        # startswith expression, checking length in case only a wildcard is provided as field value
        elif isinstance(value, str) and value.endswith("*") and len(value) > 1:
            # Issue related to * in between the string
            outputValue = self.cleanValue(re.sub("^\*|\*$", "", value))
            if self.isWildCardPresent(outputValue):
                return self.mapExpression % (key, self.generateValueNode("{}*".format(outputValue), True))
            return self.startsWithExpression % (key, self.generateValueNode(outputValue, True))
        else:
            return self.mapExpression % (key, self.generateCleanValueNodeLogsource(value))

    # Function to generate Spotter Query for rawevent in case of mapListsSpecialHandling is True and value is
    #  instance of string and integer
    def generateRaweventQueryforStringInteger(self, key, value):
        if isinstance(value, str):
            output_value = self.cleanValue(re.sub("^\*|\*$", "", value))
            if output_value:
                if self.isWildCardPresent(output_value):
                    output_value = self.generateValueNode("*{}*".format(output_value), True)
                    return self.mapExpression % (key, output_value)
                output_value = self.generateValueNode(output_value, True)
                return self.containsExpression % (key, output_value)
            else:
                return
        elif isinstance(value, int):
            output_value = self.generateValueNode(value, True)
            return self.containsExpression % (key, output_value)

    # for keywords values with space
    # keyword change starts (added keyword present in the method arguments)
    def generateValueNode(self, node, attrPresent):
        if attrPresent:
            if type(node) is int:
                return self.cleanValue(str(node))
            return self.valueExpression % (str(node).strip())
        else:
            output_value = self.cleanValue(re.sub("^\*|\*$", "", node))
            if self.isWildCardPresent(output_value):
                return 'rawevent = "*{}*"'.format(output_value.strip())
            return 'rawevent CONTAINS "{}"'.format(output_value.strip())

    # collect elements of Securonix search using OR
    def generateMapItemListNode(self, key, value):
        itemslist = list()
        result = "("
        if key == self.default_field:
            for item in value:
                output_value = self.cleanValue(re.sub("^\*|\*$", "", item))
                if output_value:
                    if self.isWildCardPresent(output_value):
                        output_value = self.generateValueNode("*{}*".format(output_value), True)
                        itemslist.append(self.mapExpression % (key, output_value))
                    else:
                        output_value = self.generateValueNode(output_value, True)
                        itemslist.append(self.containsExpression % (key, output_value))
                else:
                    return
        else:
            for item in value:
                # used generateValueNode method instead of generateCleanValueNodeLogsource previously
                itemslist.append((self.generateQueryForWildcardRule(key, item)))
        result += " OR ".join(itemslist)
        result += ")"
        return result

    # Function to determine the presence of wildcard for rawevent attribute
    def isWildCardPresent(self, value):
        if value.find("*") != -1:
            return True
        return False

    def generateAggregation(self, agg, timeframe):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("'Near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None and timeframe != None:
                    return " AND eventtime AFTER -%s | WHERE count %s %s " % (timeframe, agg.cond_op, agg.condition)
                elif agg.aggfield == None and timeframe == None:
                    return "| WHERE count %s %s" % (agg.cond_op, agg.condition)
            return ""
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None and timeframe != None:
                    return " AND eventtime AFTER -%s | STATS %s | WHERE count %s %s " % (
                        timeframe, agg.groupfield, agg.cond_op, agg.condition)
                elif agg.aggfield == None and timeframe == None:
                    return " | STATS %s | WHERE count %s %s " % (agg.groupfield, agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'DISTINCT'
                    if timeframe != None:
                        return " AND eventtime AFTER -%s | STATS %s(%s) %s | WHERE DISTINCT(%s) %s %s" % (
                            timeframe, agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.aggfield, agg.cond_op,
                            agg.condition)
            return "| STATS %s(%s) %s | WHERE DISTINCT(%s) %s %s" % (
                agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.aggfield or "", agg.cond_op,
                agg.condition)
