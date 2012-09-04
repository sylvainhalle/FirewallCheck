package ca.uqac.logic.vl;

import ca.uqac.net.rules.*;

public class Intersect extends Relation
{
  public boolean inRelation(FirewallRule r1, FirewallRule r2)
  {
    if (r1.fieldBeg(m_fieldName) >= r2.fieldBeg(m_fieldName) && r1.fieldBeg(m_fieldName) <= r2.fieldEnd(m_fieldName))
      return true;
    if (r1.fieldEnd(m_fieldName) >= r2.fieldBeg(m_fieldName) && r1.fieldEnd(m_fieldName) <= r2.fieldEnd(m_fieldName))
      return true;
    if (r2.fieldBeg(m_fieldName) >= r1.fieldBeg(m_fieldName) && r2.fieldBeg(m_fieldName) <= r1.fieldEnd(m_fieldName))
      return true;
    if (r2.fieldEnd(m_fieldName) >= r1.fieldBeg(m_fieldName) && r2.fieldEnd(m_fieldName) <= r1.fieldEnd(m_fieldName))
      return true;
    return false;
  }
}
