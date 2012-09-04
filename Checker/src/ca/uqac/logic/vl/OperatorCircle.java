package ca.uqac.logic.vl;

import java.util.*;

import ca.uqac.net.rules.FirewallRuleList;

public class OperatorCircle extends ModalUnaryOperator
{
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    Vector<Integer> rl2 = rl.inRelation(ruleIndex, m_relation, m_forward);
    if (rl2.size() == 0)
      return false;
    return m_operator.evaluate(rl, rl2.elementAt(0).intValue());
  }
}
