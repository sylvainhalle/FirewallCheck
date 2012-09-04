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
 * Explanation token showing the occurrence of a shadowing anomaly
 * between two firewall rules.
 * @author sylvain
 *
 */
public class ShadowingAnomalyToken extends AnomalyToken
{
  public ShadowingAnomalyToken(int device, int left, int right, boolean decision, int number)
  {
    super(device, left, right, decision, number);
  }
  
  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append("Shadowing anomaly with rule ").append(m_ruleno).append(" on Device ").append(m_deviceName).append(": [");
    sb.append(m_left).append("-").append(m_right).append("] ");
    if (m_decision)
      sb.append("accept");
    else
      sb.append("deny");
    return sb.toString();
  }
}
