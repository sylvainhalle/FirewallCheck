/*-------------------------------------------------------------------------
    Distributed Firewall Anomaly Detector
    Copyright (C) 2012  Sylvain Hallé

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------*/
package ca.uqac.dim.net.verify;

import ca.uqac.net.rules.*;

/**
 * A node is made of a routing table and an ingress firewall
 * @author sylvain
 *
 */
public class NetworkNode
{
  /**
   * The node's address
   */
  int m_address;
  
  /**
   * The ingress firewall associated to the node
   */
  FirewallRuleList m_firewall;
  
  /**
   * The routing table associated to the node
   */
  RoutingTable m_routingT;
  
  public int getAddress()
  {
    return m_address;
  }
  
  public void setAddress(int a)
  {
    m_address = a;
  }
  
  public void setFirewall(FirewallRuleList f)
  {
    m_firewall = f;
  }
  
  public void setRouter(RoutingTable r)
  {
    m_routingT = r;
  }
  
  public NetworkNode()
  {
    super();
    m_firewall = null;
    m_routingT = null;
  }
  
  public NetworkNode(String s)
  {
    this();
    boolean parse_firewall = true; 
    StringBuilder firewall_rules = new StringBuilder();
    StringBuilder routing_rules = new StringBuilder();
    String[] lines = s.split("[\r\n]");
    for (String li : lines)
    {
      li = li.trim();
      if (li.isEmpty())
        continue;
      // Ignore "comment" lines
      if (li.startsWith("#"))
        continue;
      // Retrieve node name
      if (li.startsWith("Node name:"))
      {
        String n_name = li.substring(10).trim();
        m_address = new Integer(n_name).intValue();
        continue;
      }
      if (li.startsWith("Routing table:"))
      {
        parse_firewall = false;
        continue;
      }
      if (parse_firewall)
      {
        firewall_rules.append(li).append("\n");
      }
      else
      {
        routing_rules.append(li).append("\n");
      }
      m_routingT = new RoutingTable(routing_rules.toString());
      m_firewall = new FirewallRuleList(firewall_rules.toString());
    }
  }
  
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    out.append("Node name: ").append(m_address).append("\n\n");
    out.append(m_firewall).append("\n");
    out.append("Routing table:\n\n");
    out.append(m_routingT);
    return out.toString();
  }
}
