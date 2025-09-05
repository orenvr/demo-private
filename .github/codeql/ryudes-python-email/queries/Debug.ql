/**
 * Debug query to see what AST nodes exist for our test case
 */

import python

from Assign assign, Subscript target
where 
  assign.getATarget() = target and
  assign.getLocation().getFile().getBaseName() = "vuln_demo.py"
select assign, target, target.getIndex(), assign.getValue()
