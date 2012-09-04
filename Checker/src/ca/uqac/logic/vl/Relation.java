package ca.uqac.logic.vl;

import ca.uqac.net.rules.*;

public class Relation
{
  String m_fieldName = "Source";
  
  Relation(String fieldName)
  {
    this();
    if (fieldName != null)
      m_fieldName = fieldName;
  }
  
  Relation()
  {
    super();
  }
  
  public boolean inRelation(FirewallRule r1, FirewallRule r2)
  {
    return false;
  }
}
