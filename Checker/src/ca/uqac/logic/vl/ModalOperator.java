package ca.uqac.logic.vl;

public class ModalOperator extends Operator
{
  Relation m_relation;
  boolean m_forward = true; // forward
  
  public void setRelation(Relation r)
  {
    if (r != null)
      m_relation = r;
  }
  
  public void setForward(boolean forward)
  {
    m_forward = forward;
  }
}
