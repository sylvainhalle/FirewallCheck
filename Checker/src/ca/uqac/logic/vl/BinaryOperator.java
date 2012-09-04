package ca.uqac.logic.vl;

public class BinaryOperator extends Operator
{
  protected Operator m_left;
  protected Operator m_right;
  
  public void setLeft(Operator o)
  {
    if (o != null)
      m_left = o;
  }
  
  public void setRight(Operator o)
  {
    if (o != null)
      m_right = o;
  }
}
