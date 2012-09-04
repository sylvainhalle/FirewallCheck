package ca.uqac.logic.vl;

import ca.uqac.net.rules.FirewallRuleList;

public class OperatorNot extends ModalUnaryOperator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    return !m_operator.evaluate(rl, ruleIndex);
  }
}
