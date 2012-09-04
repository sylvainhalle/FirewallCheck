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

/**
 * Explanation token pointing to a specific firewall rule
 * that will later be confronted to another rule to show the
 * presence of an anomaly.
 * @author sylvain
 *
 */
public class FirewallRuleToken extends ExplanationToken
{ 
  /**
   * Decision
   */
  protected boolean m_decision;
  
  /**
   * Rule number in the firewall rule base
   */
  protected int m_number;
  
  /**
   * Beginning and end of the rule's interval
   */
  protected int m_beg;
  protected int m_end;
  
  /**
   * Constructs a FirewallRuleToken
   * @param number Rule number in the firewall rule base
   * @param begin Beginning of the rule's interval
   * @param end End of the rule's interval
   * @param decision Rule decision (accept/deny)
   * @param device The device on which the rule is processed
   */
  public FirewallRuleToken(int number, int begin, int end, boolean decision, int device)
  {
    super();
    m_number = number;
    m_beg = begin;
    m_end = end;
    m_decision = decision;
    m_deviceName = device;
  }
 
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    out.append("Considering firewall rule ").append(m_number).append(" on Device ").append(m_deviceName);
    out.append(": [").append(m_beg).append("-").append(m_end).append("] ");
    if (m_decision)
      out.append("accept");
    else
      out.append("reject");
    return out.toString();
  }
}
