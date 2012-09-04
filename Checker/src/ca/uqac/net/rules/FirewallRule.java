package ca.uqac.net.rules;

/**
 * A firewall rule is a rule whose decision is a Boolean: true stands for
 * accepting the packet, false stands for rejecting the packet.
 * @author sylvain
 *
 */
public class FirewallRule extends Rule<Boolean>
{

  public FirewallRule(String s)
  {
    super();
    String fields[] = s.split("[:|;|,]");
    m_fieldBegs.put("Source", new Integer(fields[1].trim()).intValue());
    m_fieldEnds.put("Source", new Integer(fields[2].trim()).intValue());
    m_fieldBegs.put("Destination", new Integer(fields[4].trim()).intValue());
    m_fieldEnds.put("Destination", new Integer(fields[5].trim()).intValue());
    // We ignore ports at the moment
    if (fields[7].trim().compareToIgnoreCase("accept") == 0)
      m_decision = true;
    else
    	m_decision = false;
  }
  
  public String toString()
  {
    StringBuffer sb = new StringBuffer();
    sb.append(m_fieldBegs.get("Source")).append(", ").append(m_fieldEnds.get("Source")).append(" : 0, ");
    sb.append(m_fieldBegs.get("Destination")).append(", ").append(m_fieldEnds.get("Destination")).append(" : 0, ");
    if (m_decision)
      sb.append("accept");
    else
      sb.append("deny");
    return sb.toString();
  }

}
