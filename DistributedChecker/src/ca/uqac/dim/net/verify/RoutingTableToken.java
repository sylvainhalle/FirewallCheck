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
 * Explanation token indicating that a specific rule of some device's
 * routing table is being taken.
 * @author sylvain
 *
 */
public class RoutingTableToken extends ExplanationToken
{
  /**
   * The rule's destination (i.e. next hop)
   */
  protected int m_destination;
  
  /**
   * Beginning and end of the rule's interval
   */
  protected int m_beg;
  protected int m_end;
  
  public RoutingTableToken(int begin, int end, int destination, int device)
  {
    m_beg = begin;
    m_end = end;
    m_destination = destination;
    m_deviceName = device;
  }
  
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    out.append("On Device ").append(m_deviceName);
    out.append(", taking routing rule: [").append(m_beg).append("-").append(m_end).append("] -> Device ").append(m_destination);
    return out.toString();
  }
}
