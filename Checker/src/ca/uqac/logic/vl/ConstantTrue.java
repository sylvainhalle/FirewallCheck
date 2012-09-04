package ca.uqac.logic.vl;

import ca.uqac.net.rules.FirewallRuleList;

public class ConstantTrue extends Operator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    return true;
  }
}
