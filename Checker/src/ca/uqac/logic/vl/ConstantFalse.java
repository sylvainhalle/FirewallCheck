package ca.uqac.logic.vl;

import ca.uqac.net.rules.FirewallRuleList;

public class ConstantFalse extends Operator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    return false;
  }
}
