package ca.uqac.logic.vl;

import ca.uqac.net.rules.FirewallRuleList;

public class OperatorOr extends BinaryOperator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    return m_left.evaluate(rl, ruleIndex) || m_right.evaluate(rl, ruleIndex);
  }
}
