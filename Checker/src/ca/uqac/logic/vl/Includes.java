package ca.uqac.logic.vl;

import ca.uqac.net.rules.*;

public class Includes extends Relation
{ 
  
  public boolean inRelation(FirewallRule r1, FirewallRule r2)
  {
    return (r1.fieldBeg(m_fieldName) <= r2.fieldBeg(m_fieldName) &&
        r1.fieldEnd(m_fieldName) >= r2.fieldEnd(m_fieldName));
  }
}
