package edu.purdue.cs.pursec.appagent.codec;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.codec.CodecContext;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.constraint.*;

import static com.google.common.base.Preconditions.checkNotNull;

public final class MyEncodeConstraintCodecHelper {

    private final Constraint constraint;
    private final CodecContext context;

    /**
     * Constructs a constraint encoder.
     *
     * @param constraint constraint to encode
     * @param context to use for look ups
     */
    public MyEncodeConstraintCodecHelper(Constraint constraint, CodecContext context) {
        this.constraint = constraint;
        this.context = context;
    }

    /**
     * Encodes a latency constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeLatencyConstraint() {
        checkNotNull(constraint, "Duration constraint cannot be null");
        final LatencyConstraint latencyConstraint =
                (LatencyConstraint) constraint;
        return context.mapper().createObjectNode()
                .put("latencyMillis", latencyConstraint.latency().toMillis());
    }

    /**
     * Encodes an obstacle constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeObstacleConstraint() {
        checkNotNull(constraint, "Obstacle constraint cannot be null");
        final ObstacleConstraint obstacleConstraint =
                (ObstacleConstraint) constraint;

        final ObjectNode result = context.mapper().createObjectNode();
        final ArrayNode jsonObstacles = result.putArray("obstacles");

        for (DeviceId did : obstacleConstraint.obstacles()) {
            jsonObstacles.add(did.toString());
        }

        return result;
    }

    /**
     * Encodes a waypoint constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeWaypointConstraint() {
        checkNotNull(constraint, "Waypoint constraint cannot be null");
        final WaypointConstraint waypointConstraint =
                (WaypointConstraint) constraint;

        final ObjectNode result = context.mapper().createObjectNode();
        final ArrayNode jsonWaypoints = result.putArray("waypoints");

        for (DeviceId did : waypointConstraint.waypoints()) {
            jsonWaypoints.add(did.toString());
        }

        return result;
    }

    /**
     * Encodes a annotation constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeAnnotationConstraint() {
        checkNotNull(constraint, "Annotation constraint cannot be null");
        final AnnotationConstraint annotationConstraint =
                (AnnotationConstraint) constraint;
        return context.mapper().createObjectNode()
                .put("key", annotationConstraint.key())
                .put("threshold", annotationConstraint.threshold());
    }

    /**
     * Encodes a bandwidth constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeBandwidthConstraint() {
        checkNotNull(constraint, "Bandwidth constraint cannot be null");
        final BandwidthConstraint bandwidthConstraint =
                (BandwidthConstraint) constraint;
        return context.mapper().createObjectNode()
                .put("bandwidth", bandwidthConstraint.bandwidth().bps());
    }

    /**
     * Encodes a link type constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeLinkTypeConstraint() {
        checkNotNull(constraint, "Link type constraint cannot be null");

        final LinkTypeConstraint linkTypeConstraint =
                (LinkTypeConstraint) constraint;

        final ObjectNode result = context.mapper().createObjectNode()
                .put(MyConstraintCodec.INCLUSIVE, linkTypeConstraint.isInclusive());

        final ArrayNode jsonTypes = result.putArray(MyConstraintCodec.TYPES);

        if (linkTypeConstraint.types() != null) {
            for (Link.Type type : linkTypeConstraint.types()) {
                jsonTypes.add(type.name());
            }
        }

        return result;
    }

    private ObjectNode encodeMeteredConstraint() {
        checkNotNull(constraint, "Metered constraint cannot be null");
        final MeteredConstraint meteredConstraint =
                (MeteredConstraint) constraint;
        return context.mapper().createObjectNode()
                .put("metered", meteredConstraint.isUseMetered());
    }

    /**
     * Encodes a tier constraint.
     *
     * @return JSON ObjectNode representing the constraint
     */
    private ObjectNode encodeTierConstraint() {
        checkNotNull(constraint, "Tier constraint cannot be null");
        final TierConstraint tierConstraint = (TierConstraint) constraint;

        final ObjectNode result = context.mapper().createObjectNode()
                .put(MyConstraintCodec.INCLUSIVE, tierConstraint.isInclusive())
                .put(MyConstraintCodec.COST_TYPE, tierConstraint.costType().name());

        final ArrayNode jsonTiers = result.putArray(MyConstraintCodec.TIERS);

        if (tierConstraint.tiers() != null) {
            for (Integer tier : tierConstraint.tiers()) {
                jsonTiers.add(tier);
            }
        }

        return result;
    }

    /**
     * Encodes the constraint in JSON.
     *
     * @return JSON node
     */
    public ObjectNode encode() {
        final ObjectNode result;
        if (constraint instanceof BandwidthConstraint) {
            result = encodeBandwidthConstraint();
        } else if (constraint instanceof LinkTypeConstraint) {
            result = encodeLinkTypeConstraint();
        } else if (constraint instanceof AnnotationConstraint) {
            result = encodeAnnotationConstraint();
        } else if (constraint instanceof LatencyConstraint) {
            result = encodeLatencyConstraint();
        } else if (constraint instanceof ObstacleConstraint) {
            result = encodeObstacleConstraint();
        } else if (constraint instanceof WaypointConstraint) {
            result = encodeWaypointConstraint();
        } else if (constraint instanceof MeteredConstraint) {
            result = encodeMeteredConstraint();
        } else if (constraint instanceof TierConstraint) {
            result = encodeTierConstraint();
        } else {
            result = context.mapper().createObjectNode();
        }

        result.put(MyConstraintCodec.TYPE, constraint.getClass().getSimpleName());
        return result;
    }
}
