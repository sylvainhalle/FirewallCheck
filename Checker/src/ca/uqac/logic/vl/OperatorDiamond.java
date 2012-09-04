package ca.uqac.logic.vl;

import java.util.Vector;

import ca.uqac.net.rules.FirewallRuleList;

public class OperatorDiamond extends ModalUnaryOperator
{ 
  public boolean evaluate(FirewallRuleList rl, int ruleIndex)
  {
    Vector<Integer> rl2 = rl.inRelation(ruleIndex, m_relation, m_forward);
    for (int i = 0; i < rl2.size(); i++)
    {
      if (m_operator.evaluate(rl, rl2.elementAt(i).intValue()))
        return true;
    }
    return false;
  }
}
