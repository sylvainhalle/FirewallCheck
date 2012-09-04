package ca.uqac.logic.vl;

public class ModalUnaryOperator extends ModalOperator
{
  Operator m_operator;
  
  public void setOperator(Operator o)
  {
    if (o != null)
      m_operator = o;
  }
}
