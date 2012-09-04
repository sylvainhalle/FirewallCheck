package ca.uqac.net.rules;

import java.util.*;

public class Rule<T>
{
  protected Map<String,Integer> m_fieldBegs = new HashMap<String,Integer>();
  protected Map<String,Integer> m_fieldEnds = new HashMap<String,Integer>();
  protected T m_decision; // = Deny
  
  public int fieldBeg(String fieldName)
  {
    return m_fieldBegs.get(fieldName).intValue();
  }
  
  public int fieldEnd(String fieldName)
  {
    return m_fieldEnds.get(fieldName).intValue();
  }
  
  public Rule()
  {
    super();
  }
  
  public Rule(String s)
  {
    super();
  }
  
  public String toString()
  {
    return "";
  }
  
  public T getDecision()
  {
    return m_decision;
  }
}
