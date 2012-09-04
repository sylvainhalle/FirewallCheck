package ca.uqac.logic.vl;

import ca.uqac.net.rules.*;

public class Deny extends Operator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    if (ruleIndex < 0 || ruleIndex >= rl.size())
      return false;
    FirewallRule r = rl.elementAt(ruleIndex);
    return r.getDecision() == false;
  }
}
