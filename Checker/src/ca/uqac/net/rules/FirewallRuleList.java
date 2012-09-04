package ca.uqac.net.rules;

import java.util.*;

import ca.uqac.logic.vl.Relation;

public class FirewallRuleList extends Vector<FirewallRule>
{
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  /**
   * Returns the list of rules in relation with the rule with given index
   * @param ruleIndex
   * @param rel
   * @param forward
   * @return
   */
  public Vector<Integer> inRelation(int ruleIndex, Relation rel, boolean forward)
  {
    Vector<Integer> rl = new Vector<Integer>();
    if (ruleIndex < 0 || ruleIndex >= this.size())
      return rl;
    FirewallRule r = this.elementAt(ruleIndex);
    int inc = 0;
    if (forward)
      inc = 1;
    else
      inc = -1;
    for (int i = ruleIndex + inc; i >= 0 && i < this.size(); i+= inc)
    {
      FirewallRule r2 = this.elementAt(i);
      if (rel.inRelation(r2, r))
        rl.add(new Integer(i));
    }
    return rl;
  }
  
  public FirewallRuleList()
  {
	  super();
  }
  
  /**
   * Parse a rule list from a multi-line string
   * @param s
   */
  public FirewallRuleList(String s)
  {
	  this();
    String[] lines = s.split("[\r\n]");
    for (String li : lines)
    {
      li = li.trim();
      if (li.isEmpty())
        continue;
      if (li.startsWith("#"))
        continue;
      FirewallRule r = new FirewallRule(li);
      this.add(r);
    }
  }
  
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    int c = 0;
    for (FirewallRule r : this)
    {
      out.append(c).append(": ").append(r).append("\n");
      c++;
    }
    return out.toString();
  }
}
